package main

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
)

func TestStartProxiesPreservesHostKeysAcrossServers(t *testing.T) {
	cfg := config{dataDir: t.TempDir()}
	for _, id := range []string{"edge-a", "edge-b"} {
		cfg.sshServers = append(cfg.sshServers, sshServerConfig{
			id: id, host: "127.0.0.1", port: 1, user: "test", transports: 2,
			maxClientTunnels: 1, maxPendingOpens: 1, maxPendingServiceOpens: 1,
		})
	}
	d, rules, _ := startProxies(cfg, nil, newSDStatus())
	t.Cleanup(func() {
		d.stop()
		rules.Stop()
	})
	set := d.(*sshDialerSet)
	for _, pool := range set.pools {
		store := pool.slots[0].dialer.(*sshDialer).cfg.hostKeys
		if err := store.verifyAndPin(pool.id, "SHA256:"+pool.id); err != nil {
			t.Fatal(err)
		}
	}
	reloaded := &hostKeyStore{path: cfg.dataDir + "/" + sshKnownHostsFile}
	for _, pool := range set.pools {
		if got, err := reloaded.fingerprint(pool.id); err != nil || got != "SHA256:"+pool.id {
			t.Fatalf("persisted fingerprint for %s = %q, err = %v", pool.id, got, err)
		}
		var mismatch *hostKeyMismatchError
		if err := reloaded.verifyAndPin(pool.id, "SHA256:changed"); !errors.As(err, &mismatch) {
			t.Fatalf("changed key for %s: expected host key mismatch, got %v", pool.id, err)
		}
	}
}

func TestHostKeyStorePinsPerServer(t *testing.T) {
	path := t.TempDir() + "/ssh_known_hosts"
	s := &hostKeyStore{path: path}
	if err := s.verifyAndPin("edge-a", "SHA256:first"); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyAndPin("edge-b", "SHA256:second"); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyAndPin("edge-a", "SHA256:first"); err != nil {
		t.Fatal(err)
	}
	if err := s.verifyAndPin("edge-a", "SHA256:changed"); err == nil {
		t.Fatal("changed key was accepted")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "edge-a SHA256:first\nedge-b SHA256:second\n" {
		t.Fatalf("stored pins = %q", contents)
	}
}

func TestHostKeyStoreSerializesFirstTrust(t *testing.T) {
	s := &hostKeyStore{path: t.TempDir() + "/ssh_known_hosts"}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, fp := range []string{"SHA256:first", "SHA256:second"} {
		wg.Add(1)
		go func(fp string) { defer wg.Done(); results <- s.verifyAndPin("edge-a", fp) }(fp)
	}
	wg.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if strings.Contains(err.Error(), "host key mismatch") {
			rejected++
		} else {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatalf("success=%d rejected=%d", success, rejected)
	}
}

func TestHostKeyStoreRequiresExplicitLegacyMigration(t *testing.T) {
	path := t.TempDir() + "/ssh_known_hosts"
	if err := os.WriteFile(path, []byte("SHA256:legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	s := &hostKeyStore{path: path}
	if _, err := s.fingerprint("edge-a"); err == nil || !strings.Contains(err.Error(), "assigning it to one server ID") {
		t.Fatalf("err=%v", err)
	}
}

func TestHostKeyStoreRejectsFileWithoutPins(t *testing.T) {
	for _, data := range []string{"", " \n\t", "# no pins\n"} {
		t.Run(data, func(t *testing.T) {
			path := t.TempDir() + "/" + sshKnownHostsFile
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			store := &hostKeyStore{path: path}
			if _, err := store.fingerprint("edge-a"); err == nil {
				t.Fatal("startup accepted a host key file without pins")
			}
			if err := store.verifyAndPin("edge-a", "SHA256:first"); err == nil {
				t.Fatal("trusted a new key with a host key file already present")
			}
		})
	}
}
