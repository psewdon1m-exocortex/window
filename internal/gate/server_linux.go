//go:build linux

package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type Job struct {
	ID        string    `json:"id"`
	HeadID    string    `json:"head_id"`
	Component string    `json:"component"`
	State     string    `json:"state"`
	Version   string    `json:"version,omitempty"`
	Summary   string    `json:"summary"`
	UpdatedAt time.Time `json:"updated_at"`
	Finished  bool      `json:"finished"`
}

type Server struct {
	Version         string
	Audit           *Audit
	rateMu          sync.Mutex
	rateAt          time.Time
	rateTokens      float64
	State           *State
	Reader          Reader
	ClientUID       uint32
	AdminSocket     string
	ClientSocket    string
	UpdaterSocket   string
	JobsProvider    func(context.Context) ([]Job, error)
	StorageProvider func(context.Context) ([]DockerUsage, error)
	storageCache    storageCache
}

type peerListener struct {
	*net.UnixListener
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		raw, err := connection.SyscallConn()
		var peer *syscall.Ucred
		if err == nil {
			err = raw.Control(func(fd uintptr) {
				peer, _ = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
			})
		}
		if err == nil && peer != nil && peer.Uid == l.uid {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func listenSocket(path string, mode os.FileMode, gid int, uid uint32) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("socket path must be absolute")
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("refusing to replace a non-socket")
		}
		conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil, errors.New("Window is already listening")
		}
		if !errors.Is(err, syscall.ECONNREFUSED) {
			return nil, errors.New("cannot prove old socket is stale")
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		listener.Close()
		return nil, err
	}
	if gid >= 0 {
		if err := os.Chown(path, 0, gid); err != nil {
			listener.Close()
			return nil, err
		}
	}
	return peerListener{UnixListener: listener, uid: uid}, nil
}

func (s *Server) Serve(ctx context.Context, clientGID int) error {
	if os.Geteuid() != 0 {
		return errors.New("Window broker must run under its protected root systemd unit")
	}
	admin, err := listenSocket(s.AdminSocket, 0o600, -1, 0)
	if err != nil {
		return err
	}
	defer admin.Close()
	client, err := listenSocket(s.ClientSocket, 0o660, clientGID, s.ClientUID)
	if err != nil {
		return err
	}
	defer client.Close()
	adminHTTP := &http.Server{Handler: s.AdminHandler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	clientHTTP := &http.Server{Handler: s.ClientHandler(), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 4096}
	done := make(chan error, 2)
	go func() { done <- adminHTTP.Serve(admin) }()
	go func() { done <- clientHTTP.Serve(client) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		adminHTTP.Shutdown(shutdown)
		clientHTTP.Shutdown(shutdown)
		return nil
	case err := <-done:
		return err
	}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]string{"error": message})
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		failure(w, 400, "invalid request")
		return false
	}
	return true
}

func (s *Server) AdminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, struct {
			Status
			Version string `json:"version"`
		}{s.State.Status(), s.Version})
	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"status": "ok", "version": s.Version})
	})
	mux.HandleFunc("POST /v1/pair", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Key string `json:"key"`
		}
		if !decode(w, r, &input) {
			return
		}
		status, err := s.State.Pair(input.Key)
		if err != nil {
			failure(w, 400, err.Error())
			return
		}
		jsonResponse(w, 200, status)
	})
	mux.HandleFunc("POST /v1/open", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Minutes int `json:"minutes"`
		}
		if !decode(w, r, &input) {
			return
		}
		id, status, err := s.State.Open(input.Minutes)
		if err != nil {
			failure(w, 400, err.Error())
			return
		}
		jsonResponse(w, 200, struct {
			Status
			LeaseID string `json:"lease_id"`
		}{status, id})
	})
	mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			LeaseID string `json:"lease_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		status, err := s.State.Heartbeat(input.LeaseID)
		if err != nil {
			failure(w, 403, err.Error())
			return
		}
		jsonResponse(w, 200, status)
	})
	mux.HandleFunc("POST /v1/revoke", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, s.State.Revoke())
	})
	mux.HandleFunc("POST /v1/close", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			LeaseID string `json:"lease_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		jsonResponse(w, 200, s.State.CloseIfCurrent(input.LeaseID))
	})
	mux.HandleFunc("POST /v1/live/start", func(w http.ResponseWriter, r *http.Request) {
		id, err := s.State.LiveStartCurrent()
		if err != nil {
			failure(w, 403, err.Error())
			return
		}
		jsonResponse(w, 200, map[string]any{"live": true, "lease_id": id})
	})
	mux.HandleFunc("POST /v1/live/append", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			LeaseID string `json:"lease_id"`
			Kind    string `json:"kind"`
			Text    string `json:"text"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.Text) > 2048 {
			failure(w, 400, "live event too large")
			return
		}
		if err := s.State.Append(input.LeaseID, input.Kind, input.Text); err != nil {
			failure(w, 403, err.Error())
			return
		}
		jsonResponse(w, 200, map[string]bool{"accepted": true})
	})
	mux.HandleFunc("POST /v1/live/stop", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			LeaseID string `json:"lease_id"`
		}
		if !decode(w, r, &input) {
			return
		}
		s.State.LiveStop(input.LeaseID)
		jsonResponse(w, 200, map[string]bool{"live": false})
	})
	return s.audited("admin", mux)
}

func (s *Server) ClientHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/storage", func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w) {
			return
		}
		report, err := s.storage(r.Context())
		if err != nil {
			failure(w, 503, err.Error())
			return
		}
		s.respondAllowed(w, report)
	})
	mux.HandleFunc("GET /v1/sources", func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w) {
			return
		}
		items, err := s.Reader.Sources(r.Context())
		if err != nil {
			failure(w, 503, "sources unavailable")
			return
		}
		s.respondAllowed(w, map[string]any{"sources": items})
	})
	mux.HandleFunc("POST /v1/logs", func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w) {
			return
		}
		var input struct {
			Source       string `json:"source"`
			SinceMinutes int    `json:"since_minutes"`
			Lines        int    `json:"lines"`
		}
		if !decode(w, r, &input) {
			return
		}
		result, err := s.Reader.Logs(r.Context(), input.Source, input.SinceMinutes, input.Lines)
		if err != nil {
			failure(w, 400, err.Error())
			return
		}
		s.respondAllowed(w, result)
	})
	mux.HandleFunc("GET /v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w) {
			return
		}
		jobs, err := s.jobs(r.Context())
		if err != nil {
			failure(w, 503, "Updater jobs unavailable")
			return
		}
		for i := range jobs {
			jobs[i].ID = safeJobField(jobs[i].ID)
			jobs[i].HeadID = safeJobField(jobs[i].HeadID)
			jobs[i].Component = safeJobField(jobs[i].Component)
			jobs[i].State = safeJobField(jobs[i].State)
			jobs[i].Version = safeJobField(jobs[i].Version)
			jobs[i].Summary = safeJobField(jobs[i].Summary)
		}
		s.respondAllowed(w, map[string]any{"jobs": jobs})
	})
	mux.HandleFunc("GET /v1/live", func(w http.ResponseWriter, r *http.Request) {
		if !s.allowed(w) {
			return
		}
		after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
		if err != nil {
			failure(w, 400, "invalid live cursor")
			return
		}
		events, live, err := s.State.ReadLive(after)
		if err != nil {
			failure(w, 403, err.Error())
			return
		}
		s.respondAllowed(w, map[string]any{"events": events, "live": live})
	})
	return s.audited("client", mux)
}

func safeJobField(value string) string {
	clean, omitted := Filter(value)
	if omitted {
		return "[job field omitted by Window filter]"
	}
	return clean
}

func (s *Server) respondAllowed(w http.ResponseWriter, value any) {
	if err := s.State.FinishRead(func() { jsonResponse(w, 200, value) }); err != nil {
		failure(w, 403, err.Error())
	}
}

func (s *Server) allowed(w http.ResponseWriter) bool {
	if err := s.State.Check(); err != nil {
		failure(w, 403, err.Error())
		return false
	}
	return true
}

func (s *Server) jobs(ctx context.Context) ([]Job, error) {
	if s.JobsProvider != nil {
		return s.JobsProvider(ctx)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", s.UpdaterSocket)
	}}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "http://updater.local/v1/overview", nil)
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("Updater returned %d", response.StatusCode)
	}
	var view struct {
		Jobs []Job `json:"jobs"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 512*1024)).Decode(&view); err != nil {
		return nil, err
	}
	if len(view.Jobs) > 100 {
		view.Jobs = view.Jobs[:100]
	}
	return view.Jobs, nil
}
