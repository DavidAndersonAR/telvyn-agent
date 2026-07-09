// device_config_backup.go — Check "device.config_backup" (NCM, estilo Datadog).
//
// Coleta a running-config de um device de rede por SSH e manda o texto cru pro
// backend, que sanitiza → versiona por hash em noc_device_config. v1 é SÓ
// LEITURA — o agente NUNCA reescreve o equipamento (só roda comandos de
// impressão de config).
//
// As credenciais SSH (ssh_user/ssh_secret/ssh_port/secret_kind) chegam nos
// params já DECIFRADAS pelo config-pull (o backend guarda a credencial no cofre
// cifrada com Tink e a injeta só na hora de mandar o check ao agente, sobre o
// canal autenticado). O check nunca vê o segredo cifrado nem o loga.
//
// Params aceitos (cfg.Params):
//   host_id      bigint do noc_host (string) — obrigatório (identifica o device)
//   target       IP/host SSH do device       — obrigatório
//   vendor       mikrotik|cisco|fortinet|…   — obrigatório (escolhe o comando)
//   ssh_user     usuário SSH                 — obrigatório (injetado do cofre)
//   ssh_secret   senha OU chave privada PEM  — obrigatório (injetado do cofre)
//   secret_kind  password|private_key        — default password
//   ssh_port     porta SSH                   — default 22
//   timeout_seconds  timeout do comando      — default 60
package checks

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ispwatch/collector/internal/tools"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// DeviceConfigPusher manda a running-config coletada pro gateway (NCM).
// Implementado por *otlp.IngestExporter. Injetado uma vez no startup do ingest
// (mesma mecânica do DeviceMetadataPusher).
type DeviceConfigPusher interface {
	PostDeviceConfig(ctx context.Context, hostID, vendor, source, rawText, hostKey string) error
}

var deviceConfigPusher DeviceConfigPusher

// SetDeviceConfigPusher liga o emit da config coletada (chamado no startup do ingest).
func SetDeviceConfigPusher(p DeviceConfigPusher) { deviceConfigPusher = p }

// vendorConfigCommand mapeia vendor → comando SSH que IMPRIME a running-config
// (só leitura, nunca escreve). Espelha a tabela de sanitização de linhas
// voláteis do backend (NcmConfigService.VOLATILE).
var vendorConfigCommand = map[string]string{
	"mikrotik":  "/export",
	"routeros":  "/export",
	"cisco":     "show running-config",
	"cisco_ios": "show running-config",
	"fortinet":  "show full-configuration",
	"juniper":   "show configuration | display set | no-more",
	"huawei":    "display current-configuration",
	"aruba":     "show running-config",
}

const (
	defaultConfigBackupInterval   = 6 * time.Hour
	defaultConfigBackupTimeoutSec = 60
)

type deviceConfigBackupCheck struct {
	id         string
	interval   time.Duration
	hostID     string
	target     string
	vendor     string
	command    string
	sshUser    string
	sshSecret  string
	secretKind string // password | private_key
	sshPort    int
	timeout    time.Duration
	staticTags map[string]string
}

// newDeviceConfigBackupCheck é a Factory registrada em init() para
// "device.config_backup". Valida os params obrigatórios (falha silenciosa no
// Reload — o check some, os demais seguem).
func newDeviceConfigBackupCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()

	hostID := strings.TrimSpace(params["host_id"])
	if hostID == "" {
		hostID = cfg.GetHostId()
	}
	if hostID == "" {
		return nil, fmt.Errorf("device.config_backup: missing param 'host_id'")
	}
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("device.config_backup: missing param 'target'")
	}
	vendor := strings.ToLower(strings.TrimSpace(params["vendor"]))
	command, ok := vendorConfigCommand[vendor]
	if !ok {
		return nil, fmt.Errorf("device.config_backup: unsupported vendor %q", vendor)
	}
	sshUser := strings.TrimSpace(params["ssh_user"])
	if sshUser == "" {
		return nil, fmt.Errorf("device.config_backup: missing 'ssh_user' (credencial não injetada?)")
	}
	sshSecret := params["ssh_secret"]
	if sshSecret == "" {
		return nil, fmt.Errorf("device.config_backup: missing 'ssh_secret' (credencial não injetada?)")
	}
	secretKind := strings.TrimSpace(params["secret_kind"])
	if secretKind != "private_key" {
		secretKind = "password"
	}
	sshPort := parseIntParam(params, "ssh_port", 22)
	if sshPort <= 0 {
		sshPort = 22
	}
	timeoutSec := parseIntParam(params, "timeout_seconds", defaultConfigBackupTimeoutSec)
	if timeoutSec <= 0 {
		timeoutSec = defaultConfigBackupTimeoutSec
	}
	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultConfigBackupInterval
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "device.config_backup-" + hostID
	}
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &deviceConfigBackupCheck{
		id:         id,
		interval:   interval,
		hostID:     hostID,
		target:     target,
		vendor:     vendor,
		command:    command,
		sshUser:    sshUser,
		sshSecret:  sshSecret,
		secretKind: secretKind,
		sshPort:    sshPort,
		timeout:    time.Duration(timeoutSec) * time.Second,
		staticTags: tags,
	}, nil
}

func (c *deviceConfigBackupCheck) ID() string              { return c.id }
func (c *deviceConfigBackupCheck) Interval() time.Duration { return c.interval }
func (c *deviceConfigBackupCheck) Tags() map[string]string { return c.staticTags }

// Run abre SSH no device, roda o comando de impressão de config do vendor
// (só leitura) e manda o texto cru pro backend versionar. Não emite Metrics
// (retorna nil) — o "sinal" é a versão gravada; erro incrementa o contador de
// erro do check normalmente. Honra ctx.Done() via o próprio ssh.exec.
func (c *deviceConfigBackupCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if deviceConfigPusher == nil {
		return nil, fmt.Errorf("device.config_backup: pusher não injetado (SetDeviceConfigPusher)")
	}

	args := map[string]any{
		"host":    c.target,
		"user":    c.sshUser,
		"command": c.command,
		"port":    float64(c.sshPort),
		"timeout": float64(int(c.timeout.Seconds())),
	}
	if c.secretKind == "private_key" {
		args["private_key"] = c.sshSecret
	} else {
		args["password"] = c.sshSecret
	}

	res, err := (tools.SSHExec{}).Execute(ctx, args)
	if err != nil {
		return nil, fmt.Errorf("device.config_backup: ssh %s@%s: %w", c.sshUser, c.target, err)
	}
	if code, ok := res["exit_code"].(float64); ok && code != 0 {
		msg, _ := res["error"].(string)
		return nil, fmt.Errorf("device.config_backup: comando saiu %d: %s", int(code), msg)
	}
	stdout, _ := res["stdout"].(string)
	if strings.TrimSpace(stdout) == "" {
		return nil, fmt.Errorf("device.config_backup: config vazia de %s", c.target)
	}
	// TOFU: repassa a host key SSH observada (vazia quando veio known_host e já verificamos).
	hostKey, _ := res["host_key"].(string)

	if err := deviceConfigPusher.PostDeviceConfig(ctx, c.hostID, c.vendor, "running", stdout, hostKey); err != nil {
		return nil, fmt.Errorf("device.config_backup: post: %w", err)
	}
	return nil, nil
}

func init() {
	Default.Register("device.config_backup", newDeviceConfigBackupCheck)
}
