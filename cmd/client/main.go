package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	appclient "github.com/laitekin/huashunxinan/internal/client"
	"github.com/laitekin/huashunxinan/internal/logging"
)

func main() {
	logger, err := logging.New("client")
	if err != nil {
		slog.Error("configure logger", "error", err)
		os.Exit(1)
	}
	input := flag.String("input", "data/sample.json", "input JSON file")
	server := flag.String("server", "http://localhost:8080", "server base URL")
	timeout := flag.Duration("timeout", 30*time.Second, "overall request timeout")
	flag.Parse()
	if *timeout <= 0 {
		logger.Error("invalid timeout", "timeout", timeout.String())
		os.Exit(1)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // 容器内服务名和本地 server 不应意外经过系统 HTTP 代理。
	httpClient := &http.Client{Timeout: *timeout, Transport: transport}
	runner := appclient.New(httpClient, logger, os.Stdout)
	if err = runner.Run(context.Background(), appclient.Config{InputPath: *input, ServerURL: *server}); err != nil {
		logger.Error("client_failed", "error", err)
		os.Exit(1)
	}
	logger.Info("client_completed")
}
