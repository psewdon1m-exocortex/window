//go:build linux

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func serveRequest(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	var input bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&input).Encode(body)
	}
	request := httptest.NewRequest(method, path, &input)
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	return result
}

func TestAdminAndClientBoundaries(t *testing.T) {
	state, err := NewState(filepath.Join(t.TempDir(), "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	reader := Reader{TestDir: t.TempDir(), Run: func(context.Context, string, ...string) ([]byte, error) { return []byte("line\n"), nil }}
	server := &Server{State: state, Reader: reader, Version: "0.0.1", JobsProvider: func(context.Context) ([]Job, error) {
		return []Job{{ID: "job-1", State: "COMPLETED", Summary: "token=should-not-escape"}}, nil
	}, StorageProvider: func(context.Context) ([]DockerUsage, error) {
		return []DockerUsage{{Type: "Images", TotalCount: "85", Reclaimable: "16GB"}}, nil
	}}
	client, admin := server.ClientHandler(), server.AdminHandler()
	if result := serveRequest(client, "GET", "/v1/sources", nil); result.Code != 403 {
		t.Fatalf("closed gate returned %d", result.Code)
	}
	if result := serveRequest(client, "GET", "/v1/storage", nil); result.Code != 403 {
		t.Fatal("closed gate returned storage")
	}
	if result := serveRequest(client, "POST", "/v1/pair", map[string]string{"key": testPublicKey(t)}); result.Code != 404 {
		t.Fatal("client could pair")
	}
	if result := serveRequest(admin, "POST", "/v1/pair", map[string]string{"key": testPublicKey(t)}); result.Code != 200 {
		t.Fatalf("pair: %d %s", result.Code, result.Body.String())
	}
	opened := serveRequest(admin, "POST", "/v1/open", map[string]int{"minutes": 1})
	if opened.Code != 200 {
		t.Fatalf("open: %d %s", opened.Code, opened.Body.String())
	}
	var grant struct {
		LeaseID string `json:"lease_id"`
	}
	if err := json.Unmarshal(opened.Body.Bytes(), &grant); err != nil || len(grant.LeaseID) != 48 {
		t.Fatal("lease missing")
	}
	if result := serveRequest(client, "GET", "/v1/sources", nil); result.Code != 200 {
		t.Fatal("open grant denied sources")
	}
	if result := serveRequest(client, "GET", "/v1/jobs", nil); result.Code != 200 || !bytes.Contains(result.Body.Bytes(), []byte("job-1")) || bytes.Contains(result.Body.Bytes(), []byte("should-not-escape")) {
		t.Fatal("sanitized jobs unavailable")
	}
	if result := serveRequest(client, "GET", "/v1/storage", nil); result.Code != 200 || !bytes.Contains(result.Body.Bytes(), []byte("total_bytes")) {
		t.Fatal("storage report unavailable")
	}
	ready := false
	for i := 0; i < 50; i++ {
		result := serveRequest(client, "GET", "/v1/storage", nil)
		if result.Code == 200 && bytes.Contains(result.Body.Bytes(), []byte(`"docker_status":"ready"`)) && bytes.Contains(result.Body.Bytes(), []byte(`"reclaimable":"16GB"`)) {
			ready = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !ready {
		t.Fatal("completed Docker summary did not become readable")
	}
	if result := serveRequest(client, "POST", "/v1/logs", map[string]any{"source": "unit:../../etc/passwd", "since_minutes": 1, "lines": 1}); result.Code != 400 {
		t.Fatal("arbitrary source accepted")
	}
	if result := serveRequest(admin, "POST", "/v1/heartbeat", map[string]string{"lease_id": "wrong"}); result.Code != 403 {
		t.Fatal("wrong heartbeat accepted")
	}
	if result := serveRequest(admin, "POST", "/v1/live/start", nil); result.Code != 200 {
		t.Fatalf("live start: %d", result.Code)
	}
	if result := serveRequest(admin, "POST", "/v1/live/append", map[string]string{"lease_id": grant.LeaseID, "kind": "output", "text": "PASS"}); result.Code != 200 {
		t.Fatal("live append failed")
	}
	if result := serveRequest(client, "GET", "/v1/live?after=0", nil); result.Code != 200 || !bytes.Contains(result.Body.Bytes(), []byte("PASS")) {
		t.Fatal("live event unavailable")
	}
	if result := serveRequest(admin, "POST", "/v1/revoke", nil); result.Code != 200 {
		t.Fatal("revoke failed")
	}
	if result := serveRequest(client, "GET", "/v1/jobs", nil); result.Code != 403 {
		t.Fatal("revoke left jobs exposed")
	}
	if result := serveRequest(client, "GET", "/v1/storage", nil); result.Code != 403 {
		t.Fatal("revoke left storage exposed")
	}
}

func TestAuditMetadataAndRateLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	server := &Server{State: &State{now: time.Now}, Audit: &Audit{Path: path}}
	for i := 0; i < 31; i++ {
		_ = serveRequest(server.ClientHandler(), "GET", "/v1/sources", nil)
	}
	// The rate limiter rejects unauthenticated floods too, and the audit never
	// records request bodies or returned log text.
	result := serveRequest(server.ClientHandler(), "GET", "/v1/sources", nil)
	if result.Code != 429 {
		t.Fatalf("rate limit returned %d", result.Code)
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(body, []byte(`"status":429`)) {
		t.Fatal("bounded audit did not record denial")
	}
	bad := &Server{State: &State{now: time.Now}, Audit: &Audit{Path: t.TempDir()}}
	if result := serveRequest(bad.ClientHandler(), "GET", "/v1/sources", nil); result.Code != 503 {
		t.Fatal("unavailable audit did not close reader")
	}
}
