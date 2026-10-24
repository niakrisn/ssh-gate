package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	sshKeyFile       = "ssh_key"
	firstRunDoneFile = ".first_run_done"
)

// EnsureSSHKeyPair returns the SSH public key in authorized_keys form.
// A missing private key is generated (ed25519); any other read error is
// returned: generating a new key would silently desync the server's
// authorized_keys (for example after a uid change made the file
// unreadable). The public half is always derived from the private key, so
// a stale or hand-edited ssh_key.pub is rewritten instead of printed.
func EnsureSSHKeyPair(dataDir string) (string, error) {
	privPath := filepath.Join(dataDir, sshKeyFile)
	pubPath := privPath + ".pub"

	privData, err := os.ReadFile(privPath)
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read SSH key %s: %w (check the file owner; a new key would not match authorized_keys on the server)", privPath, err)
	}

	var signer ssh.Signer
	if err == nil {
		signer, err = ssh.ParsePrivateKey(privData)
		if err != nil {
			return "", fmt.Errorf("parse existing SSH key %s: %w", privPath, err)
		}
	} else {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return "", fmt.Errorf("generate ed25519 key: %w", err)
		}
		privBytes, err := ssh.MarshalPrivateKey(priv, "")
		if err != nil {
			return "", fmt.Errorf("marshal private key: %w", err)
		}
		if err := writeFileAtomic(privPath, pem.EncodeToMemory(privBytes), 0600); err != nil {
			return "", fmt.Errorf("write private key: %w", err)
		}
		signer, err = ssh.NewSignerFromKey(priv)
		if err != nil {
			return "", fmt.Errorf("create signer: %w", err)
		}
	}

	pubKey := formatPublicKey(signer.PublicKey())
	if cur, err := os.ReadFile(pubPath); err != nil || string(cur) != pubKey {
		if err := writeFileAtomic(pubPath, []byte(pubKey), 0644); err != nil {
			return "", fmt.Errorf("write public key: %w", err)
		}
	}
	return pubKey, nil
}

// formatPublicKey returns key in authorized_keys form with an ssh-gate
// comment and no trailing newline.
func formatPublicKey(key ssh.PublicKey) string {
	return strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n") + " ssh-gate"
}
