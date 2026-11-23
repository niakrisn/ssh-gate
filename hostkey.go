package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// hostKeyStore pins one SSH host fingerprint per configured server ID.
type hostKeyStore struct {
	mu     sync.Mutex
	path   string
	pins   map[string]string
	loaded bool
}

func (s *hostKeyStore) loadLocked() error {
	if s.loaded {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read SSH host keys: %w", err)
	}
	pins := make(map[string]string)
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		line := 0
		for scanner.Scan() {
			line++
			text := strings.TrimSpace(scanner.Text())
			if text == "" || strings.HasPrefix(text, "#") {
				continue
			}
			fields := strings.Fields(text)
			if len(fields) != 2 {
				return fmt.Errorf("%s:%d: expected '<server-id> <fingerprint>'; migrate the old single fingerprint by assigning it to one server ID", filepath.Base(s.path), line)
			}
			if _, ok := pins[fields[0]]; ok {
				return fmt.Errorf("%s:%d: duplicate server ID %q", filepath.Base(s.path), line, fields[0])
			}
			if !strings.HasPrefix(fields[1], "SHA256:") {
				return fmt.Errorf("%s:%d: invalid SSH fingerprint", filepath.Base(s.path), line)
			}
			pins[fields[0]] = fields[1]
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read SSH host keys: %w", err)
		}
		if len(pins) == 0 {
			return fmt.Errorf("%s exists but has no SSH host key pins", filepath.Base(s.path))
		}
	}
	s.pins = pins
	s.loaded = true
	return nil
}

func (s *hostKeyStore) fingerprint(id string) (string, error) {
	if id == "" {
		return "", fmt.Errorf("SSH server ID is empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return "", err
	}
	return s.pins[id], nil
}

// verifyAndPin serializes the first trust decision and persists it before
// the SSH handshake can establish an authenticated transport.
func (s *hostKeyStore) verifyAndPin(id, fp string) error {
	if id == "" {
		return fmt.Errorf("SSH server ID is empty")
	}
	if !strings.HasPrefix(fp, "SHA256:") {
		return fmt.Errorf("invalid SSH host fingerprint")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadLocked(); err != nil {
		return err
	}
	if pinned := s.pins[id]; pinned != "" {
		if pinned != fp {
			return &hostKeyMismatchError{want: pinned, got: fp}
		}
		return nil
	}
	var rows strings.Builder
	ids := make([]string, 0, len(s.pins))
	for key := range s.pins {
		ids = append(ids, key)
	}
	sort.Strings(ids)
	for _, key := range ids {
		fmt.Fprintf(&rows, "%s %s\n", key, s.pins[key])
	}
	fmt.Fprintf(&rows, "%s %s\n", id, fp)
	if err := writeFileAtomic(s.path, []byte(rows.String()), 0600); err != nil {
		return fmt.Errorf("save SSH host key fingerprint for %s: %w", id, err)
	}
	s.pins[id] = fp
	return nil
}
