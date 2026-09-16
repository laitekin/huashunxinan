// Package httpapi 提供 HTTP 边界：校验请求、调用引擎、输出 JSON，并记录请求状态。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/laitekin/huashunxinan/internal/fingerprint"
)

type handler struct {
	engine *fingerprint.Engine
	logger *slog.Logger
}

// New 仅在规则加载成功后调用；健康检查因此代表服务已完成识别引擎初始化。
func New(engine *fingerprint.Engine, logger *slog.Logger) http.Handler {
	h := &handler{engine: engine, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", h.health)
	mux.HandleFunc("POST /fingerprint", h.identify)
	return observe(mux, logger)
}

func (h *handler) health(w http.ResponseWriter, r *http.Request) {
	h.writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// identify 先限制请求体、校验整个批次，再按输入顺序生成结果。
// 无法识别不是错误，不会因为 unknown 中断同一批中的其他记录。
func (h *handler) identify(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, fingerprint.MaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	var inputs []fingerprint.Input
	if err := dec.Decode(&inputs); err != nil {
		h.decodeError(w, r, err)
		return
	}
	// 确保请求只有一个 JSON 值，不接受合法数组后面拼接额外数据。
	if err := dec.Decode(new(any)); err != io.EOF {
		h.decodeError(w, r, err)
		return
	}
	if err := fingerprint.ValidateBatch(inputs); err != nil {
		h.fail(w, r, http.StatusBadRequest, "invalid_input", err.Error())
		return
	}
	results := make([]fingerprint.Result, len(inputs))
	unknown := 0
	for i, in := range inputs {
		results[i] = h.engine.Identify(in)
		if results[i].Protocol == "unknown" {
			unknown++
		}
	}
	// 只记录批次统计，不记录原始 Banner、IP 或识别结果正文。
	h.logger.Info("batch_identified", "request_id", requestID(r), "batch_size", len(inputs), "identified", len(inputs)-unknown, "unknown", unknown)
	h.writeJSON(w, r, http.StatusOK, results)
}

func (h *handler) decodeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		h.fail(w, r, http.StatusRequestEntityTooLarge, "body_too_large", fmt.Sprintf("request body exceeds %d bytes", fingerprint.MaxBodyBytes))
		return
	}
	// 不把 JSON 解析错误中的输入片段写入日志或响应，避免泄露 Banner 内容。
	h.fail(w, r, http.StatusBadRequest, "invalid_json", "expected one valid JSON array")
}

func (h *handler) fail(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	h.logger.Warn("request_rejected", "request_id", requestID(r), "status", status, "error_code", code, "reason", message)
	h.writeJSON(w, r, status, map[string]string{"error": message, "code": code, "request_id": requestID(r)})
}

func (h *handler) writeJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		h.logger.Error("response_write_failed", "request_id", requestID(r), "error", err.Error())
	}
}
