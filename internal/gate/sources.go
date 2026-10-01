package gate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
)

const MaxReadBytes = 64 * 1024

var containerName = regexp.MustCompile(`^exocortex-[a-z0-9][a-z0-9_-]{0,79}$`)
var testName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}-[0-9]{8}T[0-9]{6}-[0-9a-f]{8}$`)
var sensitive = regexp.MustCompile(`(?i)(authorization|bearer|api[_-]?key|access[_-]?key|secret|password|passwd|token|cookie|session[_-]?id|private[_-]?key|credential|BEGIN [A-Z ]*PRIVATE KEY)`)
var ansiSequence = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))`)

var fixedUnits = []string{
	"updater.service", "neptune.service", "gryphon.service", "wyvern.service", "window.service",
	"kernel.service", "volt.service", "chronos.service", "saturn.service", "laboratory.service", "perimetr.service", "mastermind.service",
	"exocortex-host-recovery.service", "docker.service", "nginx.service", "ssh.service", "sshd.service",
}

type Source struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type LogResult struct {
	Source     string   `json:"source"`
	Lines      []string `json:"lines"`
	Omitted    int      `json:"omitted"`
	ObservedAt string   `json:"observed_at"`
	Truncated  bool     `json:"truncated"`
}

type Runner func(context.Context, string, ...string) ([]byte, error)

type Reader struct {
	Run     Runner
	Now     func() time.Time
	TestDir string
}

func (r Reader) testDirectory() string {
	if r.TestDir != "" {
		return r.TestDir
	}
	return "/var/lib/window/test-results"
}

type cappedWriter struct {
	mu  sync.Mutex
	buf bytes.Buffer
	max int
}

func (w *cappedWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.buf.Len()+len(data) > w.max {
		return 0, errors.New("command output exceeded its limit")
	}
	return w.buf.Write(data)
}

func runBounded(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, name, args...)
	command.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "HOME=/nonexistent"}
	output := &cappedWriter{max: 128 * 1024}
	command.Stdout = output
	// Docker writes container stderr to this stream. Both streams share one cap.
	command.Stderr = output
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("%s read failed", name)
	}
	return output.buf.Bytes(), nil
}

func (r Reader) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r.Run != nil {
		return r.Run(ctx, name, args...)
	}
	return runBounded(ctx, name, args...)
}

func (r Reader) clock() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Reader) Sources(ctx context.Context) ([]Source, error) {
	items := make([]Source, 0, len(fixedUnits)+20)
	for _, unit := range fixedUnits {
		items = append(items, Source{ID: "unit:" + unit, Kind: "journal", Name: unit})
	}
	if entries, err := os.ReadDir(r.testDirectory()); err == nil {
		var names []string
		for _, entry := range entries {
			name := strings.TrimSuffix(entry.Name(), ".log")
			if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".log") || !testName.MatchString(name) {
				continue
			}
			names = append(names, name)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		if len(names) > 20 {
			names = names[:20]
		}
		for _, name := range names {
			items = append(items, Source{ID: "test:" + name, Kind: "test", Name: name})
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	data, err := r.run(ctx, "docker", "ps", "-a", "--format", "{{.Names}}")
	if err != nil {
		// Journald and Updater diagnostics stay available when Docker is down.
		return items, nil
	}
	seen := map[string]bool{}
	for _, name := range strings.Split(string(data), "\n") {
		name = strings.TrimSpace(name)
		if !containerName.MatchString(name) || seen[name] {
			continue
		}
		seen[name] = true
		items = append(items, Source{ID: "container:" + name, Kind: "docker", Name: name})
		if len(items) >= 109 {
			break
		}
	}
	return items, nil
}

// Filter applies the same output policy to logs and live observations. A line
// matching a known secret indicator is omitted in full. The caller reports the
// count. It cannot establish that unknown formats contain no private data.
func Filter(value string) (string, bool) {
	if sensitive.MatchString(value) || len(value) > 2048 {
		return "", true
	}
	value = ansiSequence.ReplaceAllString(value, "")
	value = strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return -1
		}
		return c
	}, value)
	return value, false
}

func (r Reader) Logs(ctx context.Context, sourceID string, sinceMinutes, lines int) (LogResult, error) {
	if sinceMinutes < 1 || sinceMinutes > 1440 || lines < 1 || lines > 200 {
		return LogResult{}, errors.New("lookback or line count exceeds the allowed range")
	}
	sources, err := r.Sources(ctx)
	if err != nil {
		return LogResult{}, err
	}
	var source Source
	for _, item := range sources {
		if item.ID == sourceID {
			source = item
			break
		}
	}
	if source.ID == "" {
		return LogResult{}, errors.New("unknown diagnostic source")
	}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	now := r.clock().UTC()
	since := now.Add(-time.Duration(sinceMinutes) * time.Minute).Format(time.RFC3339)
	var data []byte
	if source.Kind == "test" {
		path := filepath.Join(r.testDirectory(), source.Name+".log")
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > 128*1024 {
			return LogResult{}, errors.New("test result is unavailable")
		}
		data, err = os.ReadFile(path)
	} else if source.Kind == "journal" {
		data, err = r.run(ctx, "journalctl", "--no-pager", "--output=short-iso-precise", "--unit="+source.Name, "--since="+since, "--lines="+fmt.Sprint(lines))
	} else {
		data, err = r.run(ctx, "docker", "logs", "--timestamps", "--since="+since, "--tail="+fmt.Sprint(lines), source.Name)
	}
	if err != nil {
		return LogResult{}, err
	}
	result := LogResult{Source: source.ID, Lines: []string{}, ObservedAt: now.Format(time.RFC3339)}
	for _, raw := range strings.Split(string(data), "\n") {
		if raw == "" {
			continue
		}
		value, omitted := Filter(raw)
		if omitted {
			result.Omitted++
			continue
		}
		result.Lines = append(result.Lines, value)
		if len(result.Lines) == lines || totalBytes(result.Lines) >= MaxReadBytes {
			result.Truncated = true
			break
		}
	}
	return result, nil
}

func totalBytes(lines []string) int {
	size := 0
	for _, line := range lines {
		size += len(line)
	}
	return size
}
