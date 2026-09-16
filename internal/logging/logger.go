// Package logging 为 server/client 创建统一 JSON 日志；业务结果独立写入 stdout。
package logging

import (
	"fmt"
	"log/slog"
	"os"
)

// New 使用 LOG_LEVEL 控制日志级别，默认 INFO。配置错误直接返回，不静默忽略。
// stderr 适合被容器日志系统收集，也允许 client 的 stdout 重定向为结果文件。
func New(component string) (*slog.Logger, error) {
	text := os.Getenv("LOG_LEVEL")
	if text == "" {
		text = "INFO"
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(text)); err != nil {
		return nil, fmt.Errorf("invalid LOG_LEVEL: %w", err)
	}
	return slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})).With("component", component), nil
}
