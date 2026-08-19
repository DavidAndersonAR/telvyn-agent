package tools

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshDialTimeout    = 10 * time.Second
	sshDefaultPort    = 22
	sshOutputCapBytes = 256 * 1024 // 256 KiB max stdout+stderr per execution
)

// SSHExec runs a shell command on a remote host via SSH and returns
// stdout/stderr/exit_code. Credentials arrive in args and are kept on the
// stack only — never written to disk.
//
// args schema (see Django CollectorCredential.encrypted_payload + cred_ref):
//
//	host         string  required  hostname or IP
//	port         number  optional  default 22
//	user         string  required  ssh user
//	private_key  string  optional  PEM-encoded private key (RSA/Ed25519)
//	password     string  optional  password (used if private_key absent)
//	known_host   string  optional  known_hosts line for host key verification
//	command      string  required  shell command to execute
//	timeout      number  optional  seconds, default 30
//
// Exactly one of `private_key` or `password` must be provided. Public-key
// auth is preferred for production; password is supported for lab targets
// where key distribution is impractical.
type SSHExec struct{}

var unsafeSSHCommand = regexp.MustCompile(`[;&|><` + "`" + `]|\$\(|\r|\n`)

// ValidateReadOnlySSHCommand aplica a fronteira de segurança no agent. O backend
// não consegue transformar um comando mutável em permitido: o bloqueio final é local.
func ValidateReadOnlySSHCommand(vendor, command string) error {
	v := strings.ToLower(strings.TrimSpace(vendor))
	c := strings.TrimSpace(command)
	if c == "" {
		return fmt.Errorf("empty command")
	}
	if unsafeSSHCommand.MatchString(c) {
		return fmt.Errorf("shell operators and multiple commands are not allowed")
	}
	lower := strings.ToLower(c)
	allowed := false
	switch v {
	case "cisco", "ios", "ios-xe", "nx-os", "arista", "eos", "juniper", "junos", "aruba":
		allowed = strings.HasPrefix(lower, "show ") || lower == "show"
	case "fortinet", "fortigate":
		allowed = strings.HasPrefix(lower, "show ") || lower == "show" || strings.HasPrefix(lower, "get ")
	case "huawei", "h3c", "comware":
		allowed = strings.HasPrefix(lower, "display ") || lower == "display"
	case "mikrotik", "routeros":
		// RouterOS lê estado com "... print". A barra inicial é opcional no terminal.
		allowed = strings.HasSuffix(lower, " print") || lower == "print" || strings.HasSuffix(lower, "/print")
	default:
		return fmt.Errorf("unsupported vendor %q for read-only SSH", vendor)
	}
	if !allowed {
		return fmt.Errorf("command is not in the read-only allowlist for %s", vendor)
	}
	return nil
}

func (SSHExec) Name() string { return "ssh.exec" }

func (SSHExec) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	command, err := requireString(args, "command")
	if err != nil {
		return nil, err
	}
	timeoutSec := optInt(args, "timeout", 30)
	client, capturedHostKey, err := dialSSH(ctx, args)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	defer session.Close()

	// Cap output to prevent a runaway command from OOMing the Collector.
	var stdout, stderr cappedBuffer
	stdout.cap = sshOutputCapBytes
	stderr.cap = sshOutputCapBytes
	session.Stdout = &stdout
	session.Stderr = &stderr

	start := time.Now()
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- session.Run(command) }()

	var runErr error
	select {
	case <-runCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		runErr = runCtx.Err()
	case runErr = <-runErrCh:
	}
	durationMs := time.Since(start).Milliseconds()

	exitCode := 0
	exitErrMsg := ""
	if runErr != nil {
		if exitErr, ok := runErr.(*ssh.ExitError); ok {
			exitCode = exitErr.ExitStatus()
		} else {
			exitCode = -1
			exitErrMsg = runErr.Error()
		}
	}

	return map[string]any{
		"stdout":      stdout.String(),
		"stderr":      stderr.String(),
		"exit_code":   float64(exitCode), // structpb numbers are float64
		"duration_ms": float64(durationMs),
		"truncated":   stdout.truncated || stderr.truncated,
		"error":       exitErrMsg,
		"host_key":    capturedHostKey, // TOFU: known_hosts line observada (vazio se veio known_host p/ verificar)
	}, nil
}

// TestConnection autentica e abre um canal de sessão SSH sem executar comando.
func (SSHExec) TestConnection(ctx context.Context, args map[string]any) (map[string]any, error) {
	start := time.Now()
	client, _, err := dialSSH(ctx, args)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("new session: %w", err)
	}
	_ = session.Close()
	return map[string]any{
		"success":     true,
		"duration_ms": float64(time.Since(start).Milliseconds()),
		"error":       "",
	}, nil
}

func dialSSH(ctx context.Context, args map[string]any) (*ssh.Client, string, error) {
	host, err := requireString(args, "host")
	if err != nil {
		return nil, "", err
	}
	user, err := requireString(args, "user")
	if err != nil {
		return nil, "", err
	}
	port := optInt(args, "port", sshDefaultPort)
	authMethods, err := buildAuthMethods(args)
	if err != nil {
		return nil, "", err
	}

	var capturedHostKey string
	hostKeyCallback := ssh.HostKeyCallback(func(_ string, _ net.Addr, key ssh.PublicKey) error {
		capturedHostKey = host + " " + key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
		return nil
	})
	if khLine, ok := args["known_host"].(string); ok && khLine != "" {
		_, _, pubKey, _, _, err := ssh.ParseKnownHosts([]byte(khLine))
		if err != nil {
			return nil, "", fmt.Errorf("parse known_host: %w", err)
		}
		hostKeyCallback = ssh.FixedHostKey(pubKey)
	}

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         sshDialTimeout,
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialErrCh := make(chan error, 1)
	var client *ssh.Client
	go func() {
		var dialErr error
		client, dialErr = ssh.Dial("tcp", addr, cfg)
		dialErrCh <- dialErr
	}()
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case dialErr := <-dialErrCh:
		if dialErr != nil {
			return nil, "", fmt.Errorf("ssh dial %s: %w", addr, dialErr)
		}
	}
	return client, capturedHostKey, nil
}

// cappedBuffer is a bytes.Buffer that drops writes past `cap` and flips
// `truncated` so callers can report that.
type cappedBuffer struct {
	bytes.Buffer
	cap       int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len() >= b.cap {
		b.truncated = true
		return len(p), nil
	}
	remain := b.cap - b.Len()
	if len(p) > remain {
		b.truncated = true
		_, _ = b.Buffer.Write(p[:remain])
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// buildAuthMethods turns args into ssh.AuthMethod list. Exactly one of
// `private_key` or `password` must be set (server policy decides which).
func buildAuthMethods(args map[string]any) ([]ssh.AuthMethod, error) {
	pk, _ := args["private_key"].(string)
	pw, _ := args["password"].(string)
	switch {
	case pk != "" && pw != "":
		return nil, fmt.Errorf("both private_key and password provided — choose one")
	case pk != "":
		signer, err := ssh.ParsePrivateKey([]byte(pk))
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		return []ssh.AuthMethod{ssh.PublicKeys(signer)}, nil
	case pw != "":
		return []ssh.AuthMethod{ssh.Password(pw)}, nil
	default:
		return nil, fmt.Errorf("missing required arg: private_key or password")
	}
}

func requireString(args map[string]any, key string) (string, error) {
	v, ok := args[key]
	if !ok {
		return "", fmt.Errorf("missing required arg %q", key)
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("arg %q must be a non-empty string", key)
	}
	return s, nil
}

func optInt(args map[string]any, key string, def int) int {
	v, ok := args[key]
	if !ok {
		return def
	}
	// structpb numbers come in as float64
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case int64:
		return int(n)
	}
	return def
}
