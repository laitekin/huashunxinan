package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/laitekin/huashunxinan/internal/fingerprint"
	"github.com/laitekin/huashunxinan/internal/httpapi"
	"github.com/laitekin/huashunxinan/internal/logging"
)

func main() {
	logger, err := logging.New("server")
	if err != nil {
		slog.Error("configure logger", "error", err)
		os.Exit(1)
	}
	if err = run(logger); err != nil {
		logger.Error("server_failed", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	addr := flag.String("addr", ":8080", "listen address")
	rules := flag.String("rules", "rules/fingerprints.json", "rule file")
	health := flag.String("healthcheck", "", "check health URL and exit")
	flag.Parse()
	if *health != "" {
		return checkHealth(*health)
	}
	engine, err := fingerprint.Load(*rules)
	if err != nil {
		return fmt.Errorf("load rules: %w", err)
	}
	logger.Info("rules_loaded", "path", *rules, "rules", engine.RuleCount())
	srv := &http.Server{
		Addr: *addr, Handler: httpapi.New(engine, logger), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	// 先绑定端口再记录 started，保证日志出现时服务已真实监听。
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	logger.Info("server_started", "address", listener.Addr().String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	select {
	case err = <-done:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutdown_started", "reason", ctx.Err())
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = srv.Shutdown(shutdown); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		logger.Info("shutdown_completed")
	}
	return nil
}

// checkHealth 使用 server 二进制自身完成容器健康检查，scratch 镜像无需 curl/wget。
func checkHealth(endpoint string) error {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: 2 * time.Second, Transport: transport}
	resp, err := client.Get(endpoint)
	if err != nil {
		return fmt.Errorf("health request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: %s", resp.Status)
	}
	return nil
}
