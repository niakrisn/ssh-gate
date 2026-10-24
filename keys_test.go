package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestEnsureSSHKeyPairGeneratesAndReuses(t *testing.T) {
	dir := t.TempDir()
	pub, err := EnsureSSHKeyPair(dir)
	if err != nil {
		t.Fatalf("EnsureSSHKeyPair: %v", err)
	}
	if !strings.HasPrefix(pub, "ssh-ed25519 ") || !strings.HasSuffix(pub, " ssh-gate") {
		t.Fatalf("public key = %q, want ssh-ed25519 ... ssh-gate", pub)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub)); err != nil {
		t.Fatalf("public key does not parse as authorized_keys: %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, sshKeyFile))
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("private key mode = %v, want 0600", st.Mode().Perm())
	}
	again, err := EnsureSSHKeyPair(dir)
	if err != nil || again != pub {
		t.Fatalf("second call = %q, %v; want the same key", again, err)
	}
}

// TestEnsureSSHKeyPairRewritesStalePub: ssh_key.pub is derived from the
// private key; a stale one must not be printed as the key to install.
func TestEnsureSSHKeyPairRewritesStalePub(t *testing.T) {
	dir := t.TempDir()
	pub, err := EnsureSSHKeyPair(dir)
	if err != nil {
		t.Fatalf("EnsureSSHKeyPair: %v", err)
	}
	pubPath := filepath.Join(dir, sshKeyFile+".pub")
	if err := os.WriteFile(pubPath, []byte("ssh-ed25519 AAAAstale other"), 0644); err != nil {
		t.Fatalf("write stale pub: %v", err)
	}
	got, err := EnsureSSHKeyPair(dir)
	if err != nil || got != pub {
		t.Fatalf("EnsureSSHKeyPair = %q, %v; want the key derived from ssh_key", got, err)
	}
	if data, _ := os.ReadFile(pubPath); string(data) != pub {
		t.Fatalf("ssh_key.pub = %q, want it rewritten", data)
	}
}

// TestEnsureSSHKeyPairUnreadableKey: an existing but unreadable key must be
// an error, not a reason to generate a new one.
func TestEnsureSSHKeyPairUnreadableKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads files regardless of mode")
	}
	dir := t.TempDir()
	if _, err := EnsureSSHKeyPair(dir); err != nil {
		t.Fatalf("EnsureSSHKeyPair: %v", err)
	}
	privPath := filepath.Join(dir, sshKeyFile)
	before, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if err := os.Chmod(privPath, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { os.Chmod(privPath, 0600) })

	if _, err := EnsureSSHKeyPair(dir); err == nil {
		t.Fatal("EnsureSSHKeyPair with an unreadable key succeeded, want error")
	}
	os.Chmod(privPath, 0600)
	if after, _ := os.ReadFile(privPath); string(after) != string(before) {
		t.Fatal("unreadable key was replaced")
	}
}

func TestEnsureSSHKeyPairCorruptKey(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, sshKeyFile), []byte("not a key"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := EnsureSSHKeyPair(dir); err == nil {
		t.Fatal("EnsureSSHKeyPair with a corrupt key succeeded, want error")
	}
}
