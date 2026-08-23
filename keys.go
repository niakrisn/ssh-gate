package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/9seconds/mtg/v2/mtglib"
	"golang.org/x/crypto/ssh"
)

const (
	sshKeyFile       = "ssh_key"
	mtprotoSecretFile = "mtproto_secret"
	firstRunDoneFile  = ".first_run_done"
)

// EnsureSSHKeyPair returns SSH public key string.
// If private key doesn't exist, generates ed25519 keypair.
func EnsureSSHKeyPair(dataDir string) (string, error) {
	privPath := filepath.Join(dataDir, sshKeyFile)
	pubPath := privPath + ".pub"

	if privData, err := os.ReadFile(privPath); err == nil {
		if pubData, err := os.ReadFile(pubPath); err == nil {
			return string(pubData), nil
		}
		signer, err := ssh.ParsePrivateKey(privData)
		if err != nil {
			return "", fmt.Errorf("parse existing SSH key: %w", err)
		}
		pubKey := formatPublicKey(signer.PublicKey())
		if err := os.WriteFile(pubPath, []byte(pubKey), 0644); err != nil {
			return "", fmt.Errorf("write public key: %w", err)
		}
		return pubKey, nil
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 key: %w", err)
	}

	privBytes, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	if err := os.WriteFile(privPath, pem.EncodeToMemory(privBytes), 0600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return "", fmt.Errorf("create signer: %w", err)
	}
	pubKey := formatPublicKey(signer.PublicKey())
	if err := os.WriteFile(pubPath, []byte(pubKey), 0644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return pubKey, nil
}

func formatPublicKey(key ssh.PublicKey) string {
	var buf bytes.Buffer
	buf.WriteString(key.Type())
	buf.WriteByte(' ')
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(key.Marshal())
	encoder.Close()
	buf.WriteString(" mtproto-ssh")
	return buf.String()
}

func EnsureMTProtoSecret(dataDir string) (string, error) {
	secretPath := filepath.Join(dataDir, mtprotoSecretFile)

	if data, err := os.ReadFile(secretPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	s := mtglib.GenerateSecret("www.youtube.com")
	secretHex := s.Hex()

	if err := os.WriteFile(secretPath, []byte(secretHex), 0600); err != nil {
		return "", fmt.Errorf("write mtproto secret: %w", err)
	}

	return secretHex, nil
}
