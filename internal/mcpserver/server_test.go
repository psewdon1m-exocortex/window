package mcpserver

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPHelper(t *testing.T) {
	if os.Getenv("WINDOW_MCP_HELPER") != "1" {
		return
	}
	if err := Run(context.Background(), os.Getenv("WINDOW_MCP_SOCKET")); err != nil {
		t.Fatal(err)
	}
}

func TestActualStdioMCPClientAndRevocation(t *testing.T) {
	directory := t.TempDir()
	socket := filepath.Join(directory, "reader.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var closed atomic.Bool
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if closed.Load() {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"Window is closed"}`))
			return
		}
		switch r.URL.Path {
		case "/v1/sources":
			_, _ = w.Write([]byte(`{"sources":[{"id":"unit:updater.service"}]}`))
		case "/v1/logs":
			_, _ = w.Write([]byte(`{"source":"unit:updater.service","lines":["PASS"]}`))
		case "/v1/jobs":
			_, _ = w.Write([]byte(`{"jobs":[]}`))
		case "/v1/storage":
			_, _ = w.Write([]byte(`{"docker_status":"ready","root":{"total_bytes":1024}}`))
		case "/v1/live":
			_, _ = w.Write([]byte(`{"events":[],"live":false}`))
		default:
			http.NotFound(w, r)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	command := exec.Command(os.Args[0], "-test.run=^TestMCPHelper$")
	command.Env = append(os.Environ(), "WINDOW_MCP_HELPER=1", "WINDOW_MCP_SOCKET="+socket)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := mcp.NewClient(&mcp.Implementation{Name: "window-test", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: command}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tools.Tools) != 5 {
		t.Fatalf("unexpected tool inventory: %d", len(tools.Tools))
	}
	for _, tool := range tools.Tools {
		if !strings.HasPrefix(tool.Name, "window_") || tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Fatalf("unsafe tool: %+v", tool)
		}
	}
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "window_sources"})
	if err != nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("sources failed: %+v %v", result, err)
	}
	logs, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "window_logs", Arguments: map[string]any{"source": "unit:updater.service", "since_minutes": 60, "lines": 10}})
	if err != nil || logs.IsError {
		t.Fatalf("logs failed: %+v %v", logs, err)
	}
	storage, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "window_storage"})
	if err != nil || storage.IsError || len(storage.Content) != 1 {
		t.Fatalf("storage failed: %+v %v", storage, err)
	}
	closed.Store(true)
	denied, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "window_updater_jobs"})
	if err != nil || !denied.IsError {
		t.Fatalf("revocation was not reflected in MCP: %+v %v", denied, err)
	}
}
