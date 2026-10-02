package gate

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Audit struct {
	mu   sync.Mutex
	Path string
}

type auditRecord struct {
	Time   time.Time `json:"time"`
	Role   string    `json:"role"`
	Method string    `json:"method"`
	Route  string    `json:"route"`
	Status int       `json:"status"`
	Bytes  int       `json:"bytes"`
	Phase  string    `json:"phase,omitempty"`
}

func (a *Audit) Write(value auditRecord) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(a.Path), 0o700); err != nil {
		return err
	}
	if info, err := os.Lstat(a.Path); err == nil {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
			return errors.New("Window audit path is not a protected root-owned file")
		}
		if info.Size() >= 512*1024 {
			_ = os.Remove(a.Path + ".1")
			if err := os.Rename(a.Path, a.Path+".1"); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(a.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	value.Time = time.Now().UTC()
	return json.NewEncoder(file).Encode(value)
}

type auditResponse struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *auditResponse) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}
func (w *auditResponse) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(data)
	w.bytes += n
	return n, err
}

func (s *Server) audited(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := auditRoute(r.URL.Path)
		if role == "client" && s.Audit != nil {
			if err := s.Audit.Write(auditRecord{Role: role, Method: r.Method, Route: route, Phase: "request"}); err != nil {
				failure(w, 503, "Window audit is unavailable")
				return
			}
		}
		if role == "client" && !s.takeToken() {
			failure(w, 429, "Window read rate exceeded")
			if s.Audit != nil {
				_ = s.Audit.Write(auditRecord{Role: role, Method: r.Method, Route: route, Status: 429, Phase: "response"})
			}
			return
		}
		wrapped := &auditResponse{ResponseWriter: w}
		next.ServeHTTP(wrapped, r)
		if s.Audit != nil {
			_ = s.Audit.Write(auditRecord{Role: role, Method: r.Method, Route: route, Status: wrapped.status, Bytes: wrapped.bytes, Phase: "response"})
		}
	})
}

func auditRoute(path string) string {
	switch path {
	case "/v1/status", "/v1/health", "/v1/pair", "/v1/open", "/v1/heartbeat", "/v1/revoke", "/v1/close", "/v1/live/start", "/v1/live/append", "/v1/live/stop", "/v1/sources", "/v1/logs", "/v1/jobs", "/v1/live", "/v1/storage":
		return path
	default:
		return "unknown"
	}
}

func (s *Server) takeToken() bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()
	now := time.Now()
	if s.rateAt.IsZero() {
		s.rateAt, s.rateTokens = now, 30
	}
	s.rateTokens += now.Sub(s.rateAt).Seconds() * 2
	if s.rateTokens > 30 {
		s.rateTokens = 30
	}
	s.rateAt = now
	if s.rateTokens < 1 {
		return false
	}
	s.rateTokens--
	return true
}
