package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"
)

type requestIDKey struct{}

func requestID(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

// responseWriter 记录实际 HTTP 状态和写出的字节数，供请求完成日志使用。
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *responseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += n
	return n, err
}

// Unwrap 保留 net/http ResponseController 对底层 writer 的访问能力。
func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// observe 为每次请求生成 ID，记录耗时和状态，并捕获应用 panic。
// 正常健康探测使用 DEBUG 级别，避免每五秒产生一条 INFO 日志。
func observe(next http.Handler, logger *slog.Logger) http.Handler {
	prefix := time.Now().UnixNano()
	var sequence atomic.Uint64
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := fmt.Sprintf("%x-%x", prefix, sequence.Add(1))
		r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
		w.Header().Set("X-Request-ID", id)
		recorded := &responseWriter{ResponseWriter: w}
		defer func() {
			if recovered := recover(); recovered != nil {
				// 不记录 panic 值本身，因为业务 panic 可能携带原始输入。
				logger.Error("request_panicked", "request_id", id, "stack", string(debug.Stack()))
				if recorded.status == 0 {
					recorded.Header().Set("Content-Type", "application/json")
					recorded.WriteHeader(http.StatusInternalServerError)
					if err := json.NewEncoder(recorded).Encode(map[string]string{"error": "internal server error", "request_id": id}); err != nil {
						logger.Error("response_write_failed", "request_id", id, "error", err.Error())
					}
				}
			}
			status := recorded.status
			if status == 0 {
				status = http.StatusOK
			}
			level := slog.LevelInfo
			if r.URL.Path == "/health" && status == http.StatusOK {
				level = slog.LevelDebug
			}
			if status >= 500 {
				level = slog.LevelError
			}
			logger.Log(r.Context(), level, "request_completed", "request_id", id, "method", r.Method, "path", r.URL.Path, "status", status, "duration_ms", float64(time.Since(start).Microseconds())/1000, "response_bytes", recorded.bytes)
		}()
		next.ServeHTTP(recorded, r)
	})
}
