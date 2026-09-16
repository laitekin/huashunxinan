package client

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRun(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/fingerprint" {
			t.Errorf("request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-ID", "test-1")
		_, _ = io.WriteString(w, `[{"ip":"127.0.0.1","port":22,"protocol":"SSH","product":"OpenSSH","version":"9.8p1","os_hint":"","confidence":0.95}]`)
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "input.json")
	if err := os.WriteFile(path, []byte(`[{"ip":"127.0.0.1","port":22,"banner":"SSH-2.0-OpenSSH_9.8p1"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runner := New(&http.Client{Timeout: time.Second}, logger, &output)
	if err := runner.Run(context.Background(), Config{InputPath: path, ServerURL: server.URL}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"product": "OpenSSH"`) {
		t.Fatal(output.String())
	}
}

func TestResponseCountMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, `[]`) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "input.json")
	_ = os.WriteFile(path, []byte(`[{"ip":"127.0.0.1","port":22,"banner":"x"}]`), 0600)
	runner := New(server.Client(), slog.New(slog.NewTextHandler(io.Discard, nil)), io.Discard)
	err := runner.Run(context.Background(), Config{InputPath: path, ServerURL: server.URL})
	if err == nil || !strings.Contains(err.Error(), "count mismatch") {
		t.Fatalf("got %v", err)
	}
}

func TestEndpointURL(t *testing.T) {
	for _, bad := range []string{"", "localhost:8080", "ftp://example.com"} {
		if _, err := endpointURL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	got, err := endpointURL("http://localhost:8080/")
	if err != nil || got != "http://localhost:8080/fingerprint" {
		t.Fatalf("%q %v", got, err)
	}
}
