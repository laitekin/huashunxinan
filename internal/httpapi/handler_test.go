package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/laitekin/huashunxinan/internal/fingerprint"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	engine, err := fingerprint.Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	return New(engine, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRequests(t *testing.T) {
	handler := testHandler(t)
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

func TestFingerprintResponseContractAndOrder(t *testing.T) {
	handler := testHandler(t)
	body := `[
		{"ip":"2001:db8::1","port":443,"banner":"HTTP/1.1 200 OK\r\nServer: Apache/2.4.62 (Debian)"},
		{"ip":"192.0.2.10","port":12345,"banner":"opaque and unsupported"},
		{"ip":"192.0.2.11","port":6379,"banner":"redis_version:7.4.1\r\n"}
	]`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/fingerprint", strings.NewReader(body)))
	if response.Code != 200 {
		t.Fatalf("got %d body=%s", response.Code, response.Body)
	}
	var got []fingerprint.Result
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].IP != "2001:db8::1" || got[0].Protocol != "HTTP" || got[0].Product != "Apache" || got[0].Version != "2.4.62" || got[0].OSHint != "Debian" || got[0].Confidence != 0.9 {
		t.Errorf("known result: %+v", got[0])
	}
	if got[1] != (fingerprint.Result{IP: "192.0.2.10", Port: 12345, Protocol: "unknown"}) {
		t.Errorf("unknown result: %+v", got[1])
	}
	if got[2].IP != "192.0.2.11" || got[2].Protocol != "Redis" || got[2].Product != "Redis" || got[2].Version != "7.4.1" || got[2].Confidence != 0.9 {
		t.Errorf("Redis result: %+v", got[2])
	}
}

func TestBatchLimit(t *testing.T) {
	handler := testHandler(t)
	entry := `{"ip":"127.0.0.1","port":1,"banner":""}`
	body := `[` + strings.Repeat(entry+`,`, fingerprint.MaxBatchSize) + entry + `]`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("POST", "/fingerprint", strings.NewReader(body)))
	if response.Code != 400 || !strings.Contains(response.Body.String(), `"code":"invalid_input"`) {
		t.Fatalf("got %d body=%s", response.Code, response.Body)
	}
}

func TestBodyTooLarge(t *testing.T) {
	handler := testHandler(t)
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
