package health

import (
    "encoding/json"
    "net/http"
)

type healthResp struct {
    Status string `json:"status"`
}

// HealthHandler responds with a simple JSON health status.
func HealthHandler(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _ = json.NewEncoder(w).Encode(healthResp{Status: "ok"})
}
