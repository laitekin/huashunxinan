// Package client 负责文件读取和 HTTP 传输，保持命令入口简单且可测试。
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/laitekin/huashunxinan/internal/fingerprint"
)

const maxResponseBytes = 16 << 20

type Config struct {
	InputPath string
	ServerURL string
}

type Client struct {
	httpClient *http.Client
	logger     *slog.Logger
	output     io.Writer
}

func New(httpClient *http.Client, logger *slog.Logger, output io.Writer) *Client {
	return &Client{httpClient: httpClient, logger: logger, output: output}
}

// Run 在发送前验证本地数据，并验证服务端响应条数与输入严格对应。
// 业务 JSON 写 stdout，运行日志写 logger，方便脚本安全地重定向结果。
func (c *Client) Run(ctx context.Context, cfg Config) error {
	endpoint, err := endpointURL(cfg.ServerURL)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if len(data) > fingerprint.MaxBodyBytes {
		return fmt.Errorf("input exceeds %d bytes", fingerprint.MaxBodyBytes)
	}
	var records []fingerprint.Input
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err = decoder.Decode(&records); err != nil {
		return fmt.Errorf("parse input: %w", err)
	}
	if err = decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("parse input: expected one JSON array")
	}
	if err = fingerprint.ValidateBatch(records); err != nil {
		return fmt.Errorf("validate input: %w", err)
	}
	c.logger.Info("input_loaded", "path", cfg.InputPath, "records", len(records), "bytes", len(data))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxResponseBytes {
		return fmt.Errorf("response exceeds %d bytes", maxResponseBytes)
	}
	requestID := resp.Header.Get("X-Request-ID")
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned %s (request_id=%s): %s", resp.Status, requestID, strings.TrimSpace(string(body)))
	}
	var results []fingerprint.Result
	if err = json.Unmarshal(body, &results); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(results) != len(records) {
		return fmt.Errorf("response count mismatch: sent %d, received %d", len(records), len(results))
	}
	c.logger.Info("results_received", "request_id", requestID, "records", len(results))
	encoder := json.NewEncoder(c.output)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(results); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func endpointURL(base string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(base))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return "", fmt.Errorf("server must be an absolute HTTP(S) URL")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/") + "/fingerprint"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String(), nil
}
