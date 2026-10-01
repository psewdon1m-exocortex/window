//go:build linux

package gate

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestUnixPeerUIDAndSocketPathBoundary(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "reader.sock")
	listener, err := listenSocket(path, 0o600, -1, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("reader socket mode is not private")
	}
	accepted := make(chan net.Conn, 1)
	go func() { connection, _ := listener.Accept(); accepted <- connection }()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case connection := <-accepted:
		if connection == nil {
			t.Fatal("matching UID rejected")
		}
		connection.Close()
	case <-time.After(time.Second):
		t.Fatal("matching UID not accepted")
	}
	listener.Close()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenSocket(path, 0o600, -1, uint32(os.Geteuid())); err == nil {
		t.Fatal("regular file replaced as socket")
	}
}

func TestDifferentUnixPeerUIDIsRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.sock")
	listener, err := listenSocket(path, 0o600, -1, uint32(os.Geteuid()+1))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, _ := listener.Accept()
		if connection != nil {
			connection.Close()
		}
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 1)
	if _, err := client.Read(buffer); err == nil {
		t.Fatal("wrong UID kept an open socket")
	}
}
