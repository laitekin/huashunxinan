package httpapi

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laitekin/huashunxinan/internal/fingerprint"
)

func TestRequests(t *testing.T) {
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := New(engine, logger)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/health", "", 200},
		{"POST", "/fingerprint", `[{"ip":"127.0.0.1","port":22,"banner":"random"}]`, 200},
		{"POST", "/fingerprint", `[]`, 200},
		{"POST", "/fingerprint", `null`, 400},
		{"POST", "/fingerprint", `{`, 400},
		{"POST", "/fingerprint", `[] []`, 400},
		{"POST", "/fingerprint", `[{"ip":"bad","port":0}]`, 400},
		{"GET", "/fingerprint", "", 405},
	} {
		t.Run(tc.method+tc.path+tc.body, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body)))
			if response.Code != tc.status {
				t.Fatalf("got %d body=%s", response.Code, response.Body)
			}
			if response.Header().Get("Content-Type") != "application/json" && tc.status != 405 {
				t.Errorf("content type: %q", response.Header().Get("Content-Type"))
			}
			if response.Header().Get("X-Request-ID") == "" {
				t.Error("missing request ID")
			}
		})
	}
}

func TestBodyTooLarge(t *testing.T) {
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	handler := New(engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
	response := httptest.NewRecorder()
	body := `[{"ip":"127.0.0.1","port":1,"banner":"` + strings.Repeat("x", fingerprint.MaxBodyBytes) + `"}]`
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/fingerprint", strings.NewReader(body)))
	if response.Code != 413 {
		t.Fatalf("got %d body=%s", response.Code, response.Body)
	}
	if !strings.Contains(response.Body.String(), `"code":"body_too_large"`) {
		t.Fatal(response.Body)
	}
}
