//go:build linux

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

type FilesystemUsage struct {
	TotalBytes     uint64 `json:"total_bytes"`
	UsedBytes      uint64 `json:"used_bytes"`
	AvailableBytes uint64 `json:"available_bytes"`
	ReservedBytes  uint64 `json:"reserved_bytes"`
}

type DockerUsage struct {
	Type        string `json:"type"`
	TotalCount  string `json:"total_count"`
	Active      string `json:"active"`
	Size        string `json:"size"`
	Reclaimable string `json:"reclaimable"`
}

type StorageReport struct {
	MeasuredAt   time.Time       `json:"measured_at"`
	Root         FilesystemUsage `json:"root"`
	SyslogBytes  uint64          `json:"syslog_bytes"`
	DockerStatus string          `json:"docker_status"`
	Docker       []DockerUsage   `json:"docker,omitempty"`
}

type storageCache struct {
	mu       sync.Mutex
	started  bool
	measured time.Time
	items    []DockerUsage
	status   string
}

type storageOutput struct {
	mu       sync.Mutex
	data     []byte
	exceeded bool
}

func (out *storageOutput) Write(data []byte) (int, error) {
	out.mu.Lock()
	defer out.mu.Unlock()
	remaining := 32*1024 - len(out.data)
	if len(data) > remaining {
		out.exceeded = true
	}
	out.data = append(out.data, data[:min(len(data), remaining)]...)
	return len(data), nil
}

func rootUsage() (FilesystemUsage, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return FilesystemUsage{}, err
	}
	size := uint64(stat.Bsize)
	return FilesystemUsage{TotalBytes: stat.Blocks * size, UsedBytes: (stat.Blocks - stat.Bfree) * size,
		AvailableBytes: stat.Bavail * size, ReservedBytes: (stat.Bfree - stat.Bavail) * size}, nil
}

func dockerUsage(ctx context.Context) ([]DockerUsage, error) {
	command := exec.CommandContext(ctx, "docker", "system", "df", "--format", "{{json .}}")
	output := &storageOutput{}
	command.Stdout, command.Stderr = output, output
	err := command.Run()
	if err != nil || output.exceeded {
		return nil, errors.New("Docker storage summary is unavailable")
	}
	items := []DockerUsage{}
	for _, line := range bytes.Split(bytes.TrimSpace(output.data), []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		var item DockerUsage
		if json.Unmarshal(line, &item) != nil || item.Type == "" || len(items) == 4 {
			return nil, errors.New("Docker storage summary is invalid")
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Server) storage(ctx context.Context) (StorageReport, error) {
	root, err := rootUsage()
	if err != nil {
		return StorageReport{}, errors.New("root filesystem summary is unavailable")
	}
	report := StorageReport{MeasuredAt: time.Now().UTC(), Root: root, DockerStatus: "pending"}
	if info, err := os.Stat("/var/log/syslog"); err == nil && info.Mode().IsRegular() {
		report.SyslogBytes = uint64(info.Size())
	}
	s.storageCache.mu.Lock()
	if !s.storageCache.started || time.Since(s.storageCache.measured) > 5*time.Minute {
		s.storageCache.started = true
		s.storageCache.measured = time.Now()
		s.storageCache.status = "pending"
		provider := s.StorageProvider
		if provider == nil {
			provider = dockerUsage
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			items, err := provider(ctx)
			s.storageCache.mu.Lock()
			defer s.storageCache.mu.Unlock()
			if err != nil {
				s.storageCache.status = "unavailable"
				s.storageCache.items = nil
			} else {
				s.storageCache.status = "ready"
				s.storageCache.items = items
			}
		}()
	}
	report.DockerStatus = s.storageCache.status
	report.Docker = append([]DockerUsage(nil), s.storageCache.items...)
	s.storageCache.mu.Unlock()
	return report, nil
}
