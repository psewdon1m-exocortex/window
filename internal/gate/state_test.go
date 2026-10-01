package gate

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPublicKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	blob := make([]byte, 4+len("ssh-ed25519")+4+len(public))
	binary.BigEndian.PutUint32(blob[:4], uint32(len("ssh-ed25519")))
	copy(blob[4:], "ssh-ed25519")
	offset := 4 + len("ssh-ed25519")
	binary.BigEndian.PutUint32(blob[offset:offset+4], uint32(len(public)))
	copy(blob[offset+4:], public)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
}

func TestPairLeaseHeartbeatRevokeAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	state, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	key := testPublicKey(t)
	if _, err := state.Pair(key); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(content), authorizedPrefix+key) {
		t.Fatal("forced command missing")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatal("public key mode incorrect")
	}
	if _, _, err := state.Open(0); err == nil {
		t.Fatal("zero grant accepted")
	}
	if _, _, err := state.Open(121); err == nil {
		t.Fatal("overlong grant accepted")
	}
	clock := time.Now()
	state.now = func() time.Time { return clock }
	id, status, err := state.Open(1)
	if err != nil || !status.Open {
		t.Fatal(err)
	}
	clock = clock.Add(8 * time.Second)
	if _, err := state.Heartbeat(id); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(13 * time.Second)
	if state.Check() == nil {
		t.Fatal("lost heartbeat kept access")
	}
	id, _, err = state.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.Heartbeat("wrong"); err == nil {
		t.Fatal("wrong lease refreshed access")
	}
	newID, _, err := state.Open(1)
	if err != nil {
		t.Fatal(err)
	}
	if !state.CloseIfCurrent(id).Open {
		t.Fatal("old TUI closed a newer grant")
	}
	clock = clock.Add(61 * time.Second)
	if state.Check() == nil {
		t.Fatal("duration expiry kept access")
	}
	id = newID
	if !state.Revoke().Paired || state.Check() == nil {
		t.Fatal("revoke failed")
	}
	restarted, err := NewState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !restarted.Status().Paired || restarted.Status().Open {
		t.Fatal("restart restored transient grant")
	}
	if _, err := restarted.Heartbeat(id); err == nil {
		t.Fatal("old lease survived restart")
	}
}

func TestRejectSSHKeyOptionsAndMalformedBlob(t *testing.T) {
	key := testPublicKey(t)
	for _, input := range []string{"command=\"sh\" " + key, key + "\nssh-ed25519 bogus", "ssh-rsa " + strings.TrimPrefix(key, "ssh-ed25519 "), "ssh-ed25519 AAAA"} {
		if _, _, err := ValidatePublicKey(input); err == nil {
			t.Fatalf("unsafe key accepted: %q", input)
		}
	}
}
