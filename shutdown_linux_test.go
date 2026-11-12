package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestShutdownSIGTERM(t *testing.T) {
	if os.Getenv("SSH_GATE_TEST_SIGTERM") == "1" {
		main()
		return
	}
	closed := make(chan struct{}, 2)
	sshAddr, _ := startTestSSHServerWithChannelHandler(t, "", true, func(open ssh.NewChannel) error {
		ch, requests, err := open.Accept()
		if err != nil {
			return err
		}
		go ssh.DiscardRequests(requests)
		go func() {
			io.Copy(ch, ch)
			ch.Close()
			closed <- struct{}{}
		}()
		return nil
	})
	host, port, _ := net.SplitHostPort(sshAddr)
	// Reserve distinct ephemeral addresses until all three have been chosen.
	var listeners []net.Listener
	var addresses []string
	for range 3 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, ln)
		addresses = append(addresses, ln.Addr().String())
	}
	for _, ln := range listeners {
		ln.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestShutdownSIGTERM$")
	cmd.Env = append(os.Environ(), "SSH_GATE_TEST_SIGTERM=1", "SSH_HOST="+host, "SSH_PORT="+port,
		"SSH_USER=test", "DATA_DIR="+t.TempDir(), "PROXY_MODES=socks5,http",
		"HTTP_LISTEN="+addresses[0], "SOCKS5_LISTEN="+addresses[1], "HEALTH_LISTEN="+addresses[2],
		"DIRECT_RULES=", "DOH_HOST=", "TUNNEL_DNS=1.1.1.1", "LOG_LEVEL=warn", "ACCESS_LOG=off", "NOTIFY_SOCKET=")
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			cancel()
			<-waited
		}
		t.Log(output.String())
	})
	client := &http.Client{Timeout: 100 * time.Millisecond}
	defer client.CloseIdleConnections()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		resp, err := client.Get("http://" + addresses[2] + "/readyz")
		if err == nil {
			resp.Body.Close()
			ready = resp.StatusCode == 200
		}
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("child did not become ready")
	}
	httpConn, err := net.DialTimeout("tcp", addresses[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer httpConn.Close()
	httpConn.SetDeadline(time.Now().Add(8 * time.Second))
	fmt.Fprint(httpConn, "CONNECT 198.51.100.1:443 HTTP/1.1\r\nHost: 198.51.100.1:443\r\n\r\n")
	reader := bufio.NewReader(httpConn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("CONNECT: %v %v", resp, err)
	}
	socks, err := net.DialTimeout("tcp", addresses[1], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer socks.Close()
	socks.SetDeadline(time.Now().Add(8 * time.Second))
	socks.Write([]byte{5, 1, 0})
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(socks, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatalf("greeting: %x %v", greeting, err)
	}
	socks.Write([]byte{5, 1, 0, 1, 198, 51, 100, 1, 1, 187})
	reply := make([]byte, 10)
	if _, err := io.ReadFull(socks, reply); err != nil || reply[1] != 0 {
		t.Fatalf("SOCKS CONNECT: %x %v", reply, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// Existing relays hold the drain while all three listeners stop.
	for _, address := range addresses {
		stopped := false
		for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
			c, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
			if err != nil {
				stopped = true
				break
			}
			c.Close()
			time.Sleep(5 * time.Millisecond)
		}
		if !stopped {
			t.Fatalf("listener %s accepts during drain", address)
		}
	}
	payload := bytes.Repeat([]byte("drain payload\n"), 8192)
	for _, relay := range []struct {
		conn   net.Conn
		reader io.Reader
	}{{httpConn, reader}, {socks, socks}} {
		written := make(chan error, 1)
		go func() { _, err := relay.conn.Write(payload); written <- err }()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(relay.reader, got); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("payload during drain: %v", err)
		}
		if err := <-written; err != nil {
			t.Fatal(err)
		}
		relay.conn.Close()
	}
	for range 2 {
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("SSH channel survived client completion")
		}
	}
	select {
	case err := <-waited:
		finished = true
		if err != nil {
			t.Fatalf("SIGTERM exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("child did not exit after drain")
	}
}
