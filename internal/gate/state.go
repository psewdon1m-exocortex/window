package gate

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

const HeartbeatTimeout = 12 * time.Second
const MaxDuration = 120 * time.Minute
const authorizedPrefix = `restrict,command="/usr/local/bin/window mcp" `

type Status struct {
	Paired      bool      `json:"paired"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Open        bool      `json:"open"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Live        bool      `json:"live"`
}

type Event struct {
	ID   uint64    `json:"id"`
	Time time.Time `json:"time"`
	Kind string    `json:"kind"`
	Text string    `json:"text"`
}

type State struct {
	mu          sync.Mutex
	pairedKey   string
	fingerprint string
	leaseID     string
	expiresAt   time.Time
	lastBeat    time.Time
	live        bool
	events      []Event
	nextEvent   uint64
	now         func() time.Time
	keyFile     string
}

func NewState(keyFile string) (*State, error) {
	s := &State{now: time.Now, keyFile: keyFile}
	if info, err := os.Lstat(keyFile); err == nil {
		if err := secureOwned(info, false); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	data, err := os.ReadFile(keyFile)
	if err == nil {
		line := strings.TrimSpace(string(data))
		if line != "" {
			if !strings.HasPrefix(line, authorizedPrefix) {
				return nil, errors.New("paired key lacks the forced read-only command")
			}
			key := strings.TrimPrefix(line, authorizedPrefix)
			_, fp, err := ValidatePublicKey(key)
			if err != nil {
				return nil, fmt.Errorf("invalid paired key: %w", err)
			}
			s.pairedKey, s.fingerprint = key, fp
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// ValidatePublicKey accepts exactly one ed25519 public key. No key options or
// comments from untrusted input are copied into sshd's authorized_keys file.
func ValidatePublicKey(input string) (string, string, error) {
	parts := strings.Fields(input)
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "ssh-ed25519" || len(input) > 512 || strings.ContainsAny(input, "\r\n\x00") {
		return "", "", errors.New("enter one ssh-ed25519 public key")
	}
	blob, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil || len(blob) != 51 || string(blob[0:4]) != "\x00\x00\x00\x0b" || string(blob[4:15]) != "ssh-ed25519" || string(blob[15:19]) != "\x00\x00\x00\x20" {
		return "", "", errors.New("invalid ed25519 public key blob")
	}
	canonical := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	digest := sha256.Sum256(blob)
	return canonical, "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]), nil
}

func atomicPrivate(path string, body []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	for _, directory := range []string{filepath.Dir(path), filepath.Dir(filepath.Dir(path))} {
		info, err := os.Lstat(directory)
		if err != nil {
			return err
		}
		if err := secureOwned(info, true); err != nil {
			return err
		}
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".window-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	// The public key must be readable by sshd after it switches to the
	// dedicated account, while only root may replace this root-owned file.
	if err := file.Chmod(0o644); err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func secureOwned(info os.FileInfo, directory bool) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errors.New("Window pairing path must be owned by the broker and not writable by others")
	}
	return nil
}

func (s *State) Pair(input string) (Status, error) {
	key, fp, err := ValidatePublicKey(input)
	if err != nil {
		return Status{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicPrivate(s.keyFile, []byte(authorizedPrefix+key+" window-client\n")); err != nil {
		return Status{}, err
	}
	s.pairedKey, s.fingerprint = key, fp
	s.closeLocked()
	return s.statusLocked(), nil
}

func (s *State) statusLocked() Status {
	now := s.now()
	open := s.leaseID != "" && now.Before(s.expiresAt) && now.Sub(s.lastBeat) <= HeartbeatTimeout
	if !open {
		s.closeLocked()
	}
	return Status{Paired: s.pairedKey != "", Fingerprint: s.fingerprint, Open: open, ExpiresAt: s.expiresAt, Live: open && s.live}
}

func (s *State) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *State) Open(minutes int) (string, Status, error) {
	if minutes < 1 || time.Duration(minutes)*time.Minute > MaxDuration {
		return "", Status{}, errors.New("duration must be 1–120 minutes")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pairedKey == "" {
		return "", Status{}, errors.New("pair a development PC first")
	}
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "", Status{}, err
	}
	s.closeLocked()
	s.leaseID = hex.EncodeToString(bytes)
	s.lastBeat = s.now()
	s.expiresAt = s.lastBeat.Add(time.Duration(minutes) * time.Minute)
	return s.leaseID, s.statusLocked(), nil
}

func (s *State) Heartbeat(id string) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := s.statusLocked()
	if !status.Open || id == "" || id != s.leaseID {
		return status, errors.New("Window grant is closed")
	}
	s.lastBeat = s.now()
	return s.statusLocked(), nil
}

func (s *State) Check() error {
	if !s.Status().Open {
		return errors.New("Window is closed; open it from the connected Updater TUI")
	}
	return nil
}

// FinishRead serializes the final authorization check and response emission
// with revocation. Once Revoke returns, no older read can still be emitted.
func (s *State) FinishRead(write func()) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.statusLocked().Open {
		return errors.New("Window is closed")
	}
	write()
	return nil
}

func (s *State) Revoke() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	return s.statusLocked()
}

// CloseIfCurrent is used when one TUI exits. An older TUI cannot close a
// newer operator's grant; emergency revoke remains unconditional.
func (s *State) CloseIfCurrent(id string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id != "" && id == s.leaseID {
		s.closeLocked()
	}
	return s.statusLocked()
}

func (s *State) closeLocked() {
	s.leaseID = ""
	s.expiresAt = time.Time{}
	s.lastBeat = time.Time{}
	s.live = false
	s.events = nil
}

func (s *State) LiveStart(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.statusLocked().Open || id != s.leaseID {
		return errors.New("Window grant is closed")
	}
	if s.live {
		return errors.New("a live session is already active")
	}
	s.live = true
	s.events = nil
	return nil
}

// LiveStartCurrent is called only through the root-only admin socket. The
// returned lease identity stays in the observing process, never in argv.
func (s *State) LiveStartCurrent() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.statusLocked().Open {
		return "", errors.New("Window grant is closed")
	}
	if s.live {
		return "", errors.New("a live session is already active")
	}
	s.live = true
	s.events = nil
	return s.leaseID, nil
}

func (s *State) LiveStop(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id == s.leaseID {
		s.live = false
	}
}

func (s *State) Append(id, kind, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.statusLocked().Open || id != s.leaseID || !s.live {
		return errors.New("live session is closed")
	}
	if kind != "output" && kind != "command" && kind != "updater" {
		return errors.New("invalid live event")
	}
	clean, _ := Filter(value)
	if clean == "" {
		return nil
	}
	s.nextEvent++
	s.events = append(s.events, Event{ID: s.nextEvent, Time: s.now().UTC(), Kind: kind, Text: clean})
	if len(s.events) > 200 {
		s.events = append([]Event(nil), s.events[len(s.events)-200:]...)
	}
	return nil
}

func (s *State) ReadLive(after uint64) ([]Event, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.statusLocked().Open {
		return nil, false, errors.New("Window grant is closed")
	}
	items := make([]Event, 0, 100)
	for _, event := range s.events {
		if event.ID > after {
			items = append(items, event)
			if len(items) == 100 {
				break
			}
		}
	}
	return items, s.live, nil
}
