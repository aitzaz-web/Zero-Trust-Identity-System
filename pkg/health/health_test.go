package health

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

func TestHealthHandler(t *testing.T) {
    req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
    rr := httptest.NewRecorder()
    HealthHandler(rr, req)

    if rr.Code != http.StatusOK {
        t.Fatalf("expected status 200, got %d", rr.Code)
    }
    contentType := rr.Header().Get("Content-Type")
    if contentType != "application/json" {
        t.Fatalf("expected Content-Type application/json, got %s", contentType)
    }
    expected := `{"status":"ok"}`
    body := rr.Body.String()
    // Encoder appends a newline, trim it for comparison
    if len(body) > 0 && body[len(body)-1] == '\n' {
        body = body[:len(body)-1]
    }
    if body != expected {
        t.Fatalf("unexpected body: %s", body)
    }
}
