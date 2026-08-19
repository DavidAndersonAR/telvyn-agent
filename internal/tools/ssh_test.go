package tools

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startTestSSHServer brings up an in-process SSH server that accepts the
// given pubkey and runs a fixed handler returning (stdout, stderr, exit) for
// any session.exec request. Returns "host:port" and a teardown func.
func startTestSSHServer(t *testing.T, authorizedKey ssh.PublicKey,
	handler func(cmd string) (stdout, stderr string, exit int)) (string, func()) {
	t.Helper()

	hostKey := genHostKey(t)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if string(k.Marshal()) == string(authorizedKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized")
		},
	}
	cfg.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	stop := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-stop:
					return
				default:
					continue
				}
			}
			go handleConn(conn, cfg, handler)
		}
	}()

	teardown := func() {
		close(stop)
		listener.Close()
	}
	return listener.Addr().String(), teardown
}

func handleConn(conn net.Conn, cfg *ssh.ServerConfig,
	handler func(cmd string) (stdout, stderr string, exit int)) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		go func(ch ssh.Channel, requests <-chan *ssh.Request) {
			defer ch.Close()
			for req := range requests {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				// req.Payload = uint32(len) + cmd bytes
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 |
					int(req.Payload[2])<<8 | int(req.Payload[3])
				cmd := string(req.Payload[4 : 4+cmdLen])
				req.Reply(true, nil)

				stdout, stderr, exit := handler(cmd)
				ch.Write([]byte(stdout))
				ch.Stderr().Write([]byte(stderr))
				exitMsg := struct{ Status uint32 }{Status: uint32(exit)}
				ch.SendRequest("exit-status", false, ssh.Marshal(&exitMsg))
				return
			}
		}(ch, requests)
	}
}

func genHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func genClientKeyPEM(t *testing.T) (pemBytes []byte, pubKey ssh.PublicKey) {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	signer, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return pemBytes, signer.PublicKey()
}

func TestSSHExec_HappyPath(t *testing.T) {
	keyPEM, pubKey := genClientKeyPEM(t)
	addr, teardown := startTestSSHServer(t, pubKey,
		func(cmd string) (string, string, int) {
			if cmd != "show interface" {
				return "", "unknown command", 1
			}
			return "GigabitEthernet0/1 is up\n", "", 0
		})
	defer teardown()

	host, port, _ := net.SplitHostPort(addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := SSHExec{}.Execute(ctx, map[string]any{
		"host":        host,
		"port":        toFloat(port),
		"user":        "tester",
		"private_key": string(keyPEM),
		"command":     "show interface",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got := res["stdout"].(string); !strings.Contains(got, "GigabitEthernet0/1 is up") {
		t.Errorf("unexpected stdout: %q", got)
	}
	if got := res["exit_code"].(float64); got != 0 {
		t.Errorf("exit_code: got %v want 0", got)
	}
	if res["truncated"].(bool) {
		t.Errorf("expected not truncated")
	}
}

func TestSSHExec_ExitCode(t *testing.T) {
	keyPEM, pubKey := genClientKeyPEM(t)
	addr, teardown := startTestSSHServer(t, pubKey,
		func(string) (string, string, int) { return "", "boom", 7 })
	defer teardown()

	host, port, _ := net.SplitHostPort(addr)
	res, err := SSHExec{}.Execute(context.Background(), map[string]any{
		"host":        host,
		"port":        toFloat(port),
		"user":        "tester",
		"private_key": string(keyPEM),
		"command":     "anything",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res["exit_code"].(float64) != 7 {
		t.Errorf("exit_code: got %v want 7", res["exit_code"])
	}
	if !strings.Contains(res["stderr"].(string), "boom") {
		t.Errorf("stderr missing 'boom': %q", res["stderr"])
	}
}

func TestSSHExec_TestConnectionDoesNotExecuteCommand(t *testing.T) {
	keyPEM, pubKey := genClientKeyPEM(t)
	executed := make(chan struct{}, 1)
	addr, teardown := startTestSSHServer(t, pubKey,
		func(string) (string, string, int) {
			executed <- struct{}{}
			return "", "", 0
		})
	defer teardown()

	host, port, _ := net.SplitHostPort(addr)
	res, err := SSHExec{}.TestConnection(context.Background(), map[string]any{
		"host":        host,
		"port":        toFloat(port),
		"user":        "tester",
		"private_key": string(keyPEM),
	})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if res["success"] != true {
		t.Fatalf("expected successful connection, got %#v", res)
	}
	select {
	case <-executed:
		t.Fatal("credential test executed a remote command")
	default:
	}
}

func TestSSHExec_MissingArgs(t *testing.T) {
	_, err := SSHExec{}.Execute(context.Background(), map[string]any{"host": "x"})
	if err == nil {
		t.Fatal("expected error for missing user")
	}
}

func toFloat(portStr string) float64 {
	n, _ := net.LookupPort("tcp", portStr)
	return float64(n)
}
