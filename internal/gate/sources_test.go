package gate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReaderAcceptsOnlyRegisteredBoundedSources(t *testing.T) {
	var invoked [][]string
	reader := Reader{Now: func() time.Time { return time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC) }, TestDir: t.TempDir(), Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
		invoked = append(invoked, append([]string{name}, args...))
		if name == "docker" && len(args) > 0 && args[0] == "ps" {
			return []byte("exocortex-kernel\nother-container\nexocortex-kernel\n"), nil
		}
		return []byte("normal line\nAuthorization: Bearer abc\n\x1b[31mcolored\x1b[0m\n"), nil
	}}
	sources, err := reader.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range sources {
		if source.ID == "container:other-container" {
			t.Fatal("unregistered container exposed")
		}
	}
	if _, err := reader.Logs(context.Background(), "unit:../../etc/shadow", 60, 10); err == nil {
		t.Fatal("arbitrary unit accepted")
	}
	if _, err := reader.Logs(context.Background(), "container:other-container", 60, 10); err == nil {
		t.Fatal("unregistered container accepted")
	}
	if _, err := reader.Logs(context.Background(), "unit:updater.service", 60, 201); err == nil {
		t.Fatal("unbounded request accepted")
	}
	result, err := reader.Logs(context.Background(), "container:exocortex-kernel", 60, 10)
	if err != nil {
		t.Fatal(err)
	}
	if result.Omitted != 1 || len(result.Lines) != 2 || result.Lines[1] != "colored" {
		t.Fatalf("filter failed: %+v", result)
	}
	last := strings.Join(invoked[len(invoked)-1], " ")
	if !strings.Contains(last, "docker logs --timestamps --since=2026-09-30T11:00:00Z --tail=10 exocortex-kernel") {
		t.Fatalf("unsafe/unexpected Docker invocation: %s", last)
	}
}

func TestTestResultsAreFixedSourcesAndFilteredAgain(t *testing.T) {
	dir := t.TempDir()
	name := "smoke-20260930T120000-1234abcd"
	if err := os.WriteFile(filepath.Join(dir, name+".log"), []byte("PASS\nsecret=abc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "unsafe-20260930T120000-1234abcd.log")); err != nil {
		t.Fatal(err)
	}
	reader := Reader{TestDir: dir, Run: func(context.Context, string, ...string) ([]byte, error) { return nil, nil }}
	sources, err := reader.Sources(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, source := range sources {
		if source.ID == "test:"+name {
			found = true
		}
		if strings.Contains(source.ID, "unsafe") {
			t.Fatal("symlink exposed")
		}
	}
	if !found {
		t.Fatal("test result missing")
	}
	result, err := reader.Logs(context.Background(), "test:"+name, 60, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Lines) != 1 || result.Lines[0] != "PASS" || result.Omitted != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestDockerStderrIsCaptured(t *testing.T) {
	data, err := runBounded(context.Background(), "sh", "-c", "printf 'stdout\\n'; printf 'stderr\\n' >&2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "stdout") || !strings.Contains(string(data), "stderr") {
		t.Fatalf("stream missing: %q", data)
	}
}
