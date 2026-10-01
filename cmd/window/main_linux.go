//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
	"window/internal/gate"
	"window/internal/mcpserver"
)

const adminSocket = "/run/window-admin/admin.sock"
const clientSocket = "/run/window/client.sock"
const pairFile = "/var/lib/window-ssh/.ssh/authorized_keys"
const updaterSocket = "/run/exocortex-admin/updater.sock"

var version = "0.0.1-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "window:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: window serve|mcp|observe|capture-test|version")
	}
	if args[0] == "capture-test" {
		return captureTest(args[1:])
	}
	if len(args) != 1 {
		return errors.New("unexpected Window arguments")
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "serve":
		return serve()
	case "mcp":
		account, err := user.Lookup("window")
		if err != nil {
			return err
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil || os.Geteuid() != uid {
			return errors.New("MCP must run as the dedicated window SSH account")
		}
		return mcpserver.Run(context.Background(), clientSocket)
	case "observe":
		return observe()
	default:
		return errors.New("unknown Window command")
	}
}

var captureName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)

type captureWriter struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (w *captureWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	length := len(data)
	remaining := 128*1024 - len(w.data)
	if remaining < len(data) {
		w.truncated = true
		data = data[:max(0, remaining)]
	}
	w.data = append(w.data, data...)
	return length, nil
}

// The operator explicitly launches the test. The forced SSH command cannot
// reach this subcommand and the child runs as the original unprivileged user.
func captureTest(args []string) error {
	if os.Geteuid() != 0 || len(args) < 3 || args[1] != "--" || !captureName.MatchString(args[0]) {
		return errors.New("usage: sudo window capture-test NAME -- COMMAND [ARG...]")
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" || uid == "0" {
		return errors.New("launch capture-test through sudo from an unprivileged account")
	}
	operator, err := user.LookupId(uid)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	commandArgs := append([]string{"-u", operator.Username, "--"}, args[2:]...)
	command := exec.CommandContext(ctx, "runuser", commandArgs...)
	command.Env = []string{"HOME=" + operator.HomeDir, "USER=" + operator.Username, "LOGNAME=" + operator.Username, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	output := &captureWriter{}
	command.Stdout = io.MultiWriter(os.Stdout, output)
	command.Stderr = io.MultiWriter(os.Stderr, output)
	started := time.Now().UTC()
	runErr := command.Run()
	finished := time.Now().UTC()
	status := "passed"
	if runErr != nil {
		status = "failed"
	}
	nameBytes := make([]byte, 4)
	if _, err := rand.Read(nameBytes); err != nil {
		return err
	}
	name := args[0] + "-" + started.Format("20060102T150405") + "-" + hex.EncodeToString(nameBytes)
	var content strings.Builder
	fmt.Fprintf(&content, "Window test result: %s; status: %s; started: %s; finished: %s\n", args[0], status, started.Format(time.RFC3339), finished.Format(time.RFC3339))
	for _, line := range strings.Split(string(output.data), "\n") {
		clean, omitted := gate.Filter(line)
		if omitted {
			content.WriteString("[line omitted by Window filter]\n")
		} else if clean != "" {
			content.WriteString(clean + "\n")
		}
		if content.Len() >= 64*1024 {
			content.WriteString("[result truncated]\n")
			break
		}
	}
	if output.truncated {
		content.WriteString("[captured output truncated at 128 KiB]\n")
	}
	directory := "/var/lib/window/test-results"
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	path := filepath.Join(directory, name+".log")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(file, content.String()); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	pruneResults(directory)
	fmt.Fprintln(os.Stdout, "Window saved test result:", name)
	return runErr
}

func pruneResults(directory string) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".log") {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for index, name := range names {
		path := filepath.Join(directory, name)
		if index < 20 {
			if info, err := os.Lstat(path); err == nil && time.Since(info.ModTime()) < 7*24*time.Hour {
				continue
			}
		}
		_ = os.Remove(path)
	}
}

func serve() error {
	if os.Geteuid() != 0 {
		return errors.New("broker requires root")
	}
	account, err := user.Lookup("window")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	for _, directory := range []struct {
		path string
		mode os.FileMode
	}{{"/run/window-admin", 0o700}, {"/run/window", 0o755}} {
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return err
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return err
		}
	}
	state, err := gate.NewState(pairFile)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	server := gate.Server{State: state, Reader: gate.Reader{}, Audit: &gate.Audit{Path: "/var/lib/window/audit.jsonl"}, ClientUID: uint32(uid), AdminSocket: adminSocket, ClientSocket: clientSocket, UpdaterSocket: updaterSocket, Version: version}
	return server.Serve(ctx, gid)
}

func adminRequest(ctx context.Context, method, path string, input, result any) error {
	var body bytes.Buffer
	if input != nil {
		if err := json.NewEncoder(&body).Encode(input); err != nil {
			return err
		}
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", adminSocket)
	}}
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, "http://window.local"+path, &body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4096))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("Window admin request failed: %s", strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, result)
}

func observe() error {
	if os.Geteuid() != 0 || !term.IsTerminal(int(os.Stdin.Fd())) || !term.IsTerminal(int(os.Stdout.Fd())) {
		return errors.New("observed shell requires an interactive root Updater TUI")
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" || uid == "0" {
		return errors.New("start Updater TUI with sudo from an unprivileged account")
	}
	operator, err := user.LookupId(uid)
	if err != nil {
		return err
	}
	var start struct {
		LeaseID string `json:"lease_id"`
	}
	if err := adminRequest(context.Background(), "POST", "/v1/live/start", nil, &start); err != nil {
		return err
	}
	defer func() {
		var ignored any
		_ = adminRequest(context.Background(), "POST", "/v1/live/stop", map[string]string{"lease_id": start.LeaseID}, &ignored)
	}()
	command := exec.Command("runuser", "-u", operator.Username, "--", "/bin/bash", "--noprofile", "--norc")
	command.Env = []string{"TERM=" + os.Getenv("TERM"), "HOME=" + operator.HomeDir, "USER=" + operator.Username, "LOGNAME=" + operator.Username, "PATH=/usr/local/bin:/usr/bin:/bin", "LANG=C.UTF-8"}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Pdeathsig: syscall.SIGTERM}
	terminal, err := pty.Start(command)
	if err != nil {
		return err
	}
	defer terminal.Close()
	_ = pty.InheritSize(os.Stdin, terminal)
	old, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return err
	}
	defer term.Restore(int(os.Stdin.Fd()), old)
	updates := make(chan string, 128)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for line := range updates {
			var ignored any
			_ = adminRequest(context.Background(), "POST", "/v1/live/append", map[string]string{"lease_id": start.LeaseID, "kind": "output", "text": line}, &ignored)
		}
	}()
	collector := &liveCollector{lines: updates}
	stopInput := make(chan struct{})
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		copyObservedInput(int(os.Stdin.Fd()), terminal, stopInput)
	}()
	_, _ = io.Copy(io.MultiWriter(os.Stdout, collector), terminal)
	close(stopInput)
	<-inputDone
	collector.Flush()
	close(updates)
	<-done
	return command.Wait()
}

func copyObservedInput(fd int, terminal io.Writer, stop <-chan struct{}) {
	buffer := make([]byte, 4096)
	for {
		select {
		case <-stop:
			return
		default:
		}
		ready := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		count, err := unix.Poll(ready, 100)
		if err == unix.EINTR || count == 0 {
			continue
		}
		if err != nil || ready[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return
		}
		if ready[0].Revents&unix.POLLIN != 0 {
			n, err := unix.Read(fd, buffer)
			if err != nil || n == 0 {
				return
			}
			if _, err := terminal.Write(buffer[:n]); err != nil {
				return
			}
		}
	}
}

type liveCollector struct {
	buffer  []byte
	lines   chan<- string
	dropped bool
}

func (c *liveCollector) Write(data []byte) (int, error) {
	for _, value := range data {
		if value == '\n' || value == '\r' {
			c.Flush()
			continue
		}
		if c.dropped {
			continue
		}
		if len(c.buffer) >= 2048 {
			c.buffer = c.buffer[:0]
			c.dropped = true
			continue
		}
		c.buffer = append(c.buffer, value)
	}
	return len(data), nil
}

func (c *liveCollector) Flush() {
	if c.dropped {
		select {
		case c.lines <- "[long output line omitted]":
		default:
		}
		c.dropped = false
		return
	}
	if len(c.buffer) == 0 {
		return
	}
	select {
	case c.lines <- string(c.buffer):
	default:
	}
	c.buffer = c.buffer[:0]
}
