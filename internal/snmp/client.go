// Package snmp e a fonte unica do codigo SNMP do agente: tanto o tool sob
// demanda (snmp.get / snmp.walk via internal/tools) quanto o check continuo
// snmp.generic (Plan 03-02) constroem em cima de snmp.Client. Suporte a v2c
// (community-based) e a v3 (USM, auth+priv) com os 7 protocolos de cada
// familia.
//
// O Client e thin-wrapper sobre gosnmp.GoSNMP — conexao lazy, idempotente
// no Close, e Get/BulkWalk respeitam ctx via SetDeadline no socket. Um
// driver interno (snmpDriver) permite testes sem socket UDP real.
package snmp

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// defaultTimeout e usado quando Params.Timeout vier zerado.
const defaultTimeout = 5 * time.Second

// Params descreve as credenciais e endereco do alvo SNMP. Campos V3*
// sao ignorados quando Version != "v3". Senhas (V3AuthPass, V3PrivPass)
// nunca devem ser logadas — Client.String() omite por design.
type Params struct {
	// Target aceita "host" ou "host:port"; porta default e 161.
	Target string
	// Version: "v2c" (default) ou "v3". String e validada em NewClient.
	Version string
	// Timeout do socket UDP por request; default 5s.
	Timeout time.Duration

	// v2c
	Community string

	// v3
	V3User        string
	V3AuthProto   string // "NoAuth" | "MD5" | "SHA" | "SHA224"-"SHA512"
	V3AuthPass    string
	V3PrivProto   string // "NoPriv" | "DES" | "AES" | "AES192" | "AES192C" | "AES256" | "AES256C"
	V3PrivPass    string
	V3ContextName string
}

// snmpDriver e a superficie que o Client consome do gosnmp. Existe para
// permitir injecao de fake em unit tests (sem socket UDP).
type snmpDriver interface {
	Connect() error
	Get(oids []string) (*gosnmp.SnmpPacket, error)
	BulkWalk(root string, fn gosnmp.WalkFunc) error
	// Walk uses GetNext under the hood. Slower than BulkWalk but compatible
	// with v2c devices that reject GetBulk (some Mikrotik / older firmwares).
	Walk(root string, fn gosnmp.WalkFunc) error
	Close() error
	SetDeadline(t time.Time) error
	ConnReady() bool
}

// gosnmpAdapter conecta o gosnmp.GoSNMP real a interface snmpDriver.
type gosnmpAdapter struct{ s *gosnmp.GoSNMP }

func (a *gosnmpAdapter) Connect() error                                { return a.s.Connect() }
func (a *gosnmpAdapter) Get(oids []string) (*gosnmp.SnmpPacket, error) { return a.s.Get(oids) }
func (a *gosnmpAdapter) BulkWalk(root string, fn gosnmp.WalkFunc) error {
	return a.s.BulkWalk(root, fn)
}
func (a *gosnmpAdapter) Walk(root string, fn gosnmp.WalkFunc) error {
	return a.s.Walk(root, fn)
}
func (a *gosnmpAdapter) Close() error {
	if a.s == nil || a.s.Conn == nil {
		return nil
	}
	return a.s.Conn.Close()
}
func (a *gosnmpAdapter) SetDeadline(t time.Time) error {
	if a.s == nil || a.s.Conn == nil {
		return nil
	}
	return a.s.Conn.SetDeadline(t)
}
func (a *gosnmpAdapter) ConnReady() bool { return a.s != nil && a.s.Conn != nil }

// Client e o objeto compartilhado entre tools/snmp.go e checks/snmp_generic.go.
// O ciclo de vida tipico e: NewClient -> Connect (idempotente) -> Get/BulkWalk
// repetido por algum tempo -> Close. Concorrencia: nao seguro para chamadas
// concorrentes no mesmo Client (gosnmp usa um socket por instancia).
type Client struct {
	target  string // host:port resolvido
	host    string // apenas host (para HostId em metricas)
	timeout time.Duration

	// snmp e o objeto gosnmp.GoSNMP construido em NewClient — usamos
	// diretamente em campos para que os tests do mesmo pacote possam
	// inspecionar Version, Community, MsgFlags etc.
	snmp *gosnmp.GoSNMP

	driver snmpDriver

	closed bool
}

// NewClient constroi um Client (sem conectar). Valida Version, popula
// gosnmp.GoSNMP com os parametros adequados (v2c ou v3 + USM) e empacota
// no driver default. Erros tipicos: Target vazio, Version invalida,
// AuthProto/PrivProto desconhecidos, combinacao NoAuth+Priv.
func NewClient(p Params) (*Client, error) {
	target := strings.TrimSpace(p.Target)
	if target == "" {
		return nil, fmt.Errorf("snmp: Target obrigatorio")
	}
	host, port, ok := splitHostPort(target)
	if !ok {
		return nil, fmt.Errorf("snmp: Target invalido %q (esperado host ou host:port)", p.Target)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	version := strings.ToLower(strings.TrimSpace(p.Version))
	if version == "" {
		version = "v2c"
	}

	gs := &gosnmp.GoSNMP{
		Target:  host,
		Port:    port,
		Timeout: timeout,
		Retries: 1,
		MaxOids: gosnmp.MaxOids,
		// Tolera ifIndex não-monotônico (ex.: OLT Fiberhome AN5516, que retorna
		// as linhas da ifTable fora de ordem crescente). Equivale ao -Cc do
		// net-snmp; sem isso o BulkWalk aborta com "OID not increasing". A saída
		// da subárvore (prefixo root) continua encerrando o walk normalmente.
		AppOpts: map[string]interface{}{"c": true},
	}

	switch version {
	case "v2c":
		gs.Version = gosnmp.Version2c
		gs.Community = p.Community
	case "v3":
		gs.Version = gosnmp.Version3
		gs.SecurityModel = gosnmp.UserSecurityModel

		auth, err := AuthProto(firstNonEmpty(p.V3AuthProto, "NoAuth"))
		if err != nil {
			return nil, err
		}
		priv, err := PrivProto(firstNonEmpty(p.V3PrivProto, "NoPriv"))
		if err != nil {
			return nil, err
		}
		flags, err := MsgFlags(auth, priv)
		if err != nil {
			return nil, err
		}
		gs.MsgFlags = flags
		gs.ContextName = p.V3ContextName
		gs.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 p.V3User,
			AuthenticationProtocol:   auth,
			AuthenticationPassphrase: p.V3AuthPass,
			PrivacyProtocol:          priv,
			PrivacyPassphrase:        p.V3PrivPass,
		}
	default:
		return nil, fmt.Errorf("snmp: versao desconhecida %q (validas: v2c, v3)", p.Version)
	}

	return &Client{
		target:  target,
		host:    host,
		timeout: timeout,
		snmp:    gs,
		driver:  &gosnmpAdapter{s: gs},
	}, nil
}

// newClientWithDriver e usado apenas pelos testes do pacote — permite
// injetar um snmpDriver fake sem subir socket UDP.
func newClientWithDriver(d snmpDriver, target string) *Client {
	host, _, _ := splitHostPort(target)
	if host == "" {
		host = target
	}
	return &Client{
		target:  target,
		host:    host,
		timeout: defaultTimeout,
		driver:  d,
	}
}

// Target retorna o endereco completo "host:port" usado nos pacotes SNMP.
func (c *Client) Target() string { return c.target }

// Host retorna apenas o host (sem porta). E o que vira HostId nas metricas
// para que dashboards agreguem por equipamento, nao por tupla de transport.
func (c *Client) Host() string { return c.host }

// Connect abre o socket UDP. Idempotente — chamadas repetidas sao no-ops
// se a conexao ja esta viva.
func (c *Client) Connect(ctx context.Context) error {
	if c.driver.ConnReady() {
		c.applyDeadline(ctx)
		return nil
	}
	if err := c.driver.Connect(); err != nil {
		return fmt.Errorf("snmp: connect %s: %w", c.target, err)
	}
	c.applyDeadline(ctx)
	return nil
}

// Get faz um SNMP GET de OIDs escalares e retorna as PDUs cruas. PDUs
// nao-numericas (OctetString, OID) ficam no resultado — quem chama decide
// se descarta com PduFloat ou usa Value direto (caso do sysObjectID).
func (c *Client) Get(ctx context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	if err := c.Connect(ctx); err != nil {
		return nil, err
	}
	c.applyDeadline(ctx)
	stopCancelWatch := c.watchCancel(ctx)
	defer stopCancelWatch()
	pkt, err := c.driver.Get(oids)
	if err != nil {
		return nil, fmt.Errorf("snmp get %s: %w", c.target, err)
	}
	return pkt.Variables, nil
}

// BulkWalk percorre a sub-arvore enraizada em root, chamando fn para cada
// PDU descoberta. Para no primeiro erro retornado por fn.
func (c *Client) BulkWalk(ctx context.Context, root string, fn func(gosnmp.SnmpPDU) error) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	c.applyDeadline(ctx)
	stopCancelWatch := c.watchCancel(ctx)
	defer stopCancelWatch()
	if err := c.driver.BulkWalk(root, gosnmp.WalkFunc(fn)); err != nil {
		return fmt.Errorf("snmp walk %s %s: %w", c.target, root, err)
	}
	return nil
}

// Walk percorre a sub-arvore com GetNext (uma PDU por request). Mais lento que
// BulkWalk mas funciona em devices v2c que rejeitam GetBulk — observado em
// algumas tabelas do Mikrotik RouterOS (LLDP-MIB rem table, por exemplo).
func (c *Client) Walk(ctx context.Context, root string, fn func(gosnmp.SnmpPDU) error) error {
	if err := c.Connect(ctx); err != nil {
		return err
	}
	c.applyDeadline(ctx)
	stopCancelWatch := c.watchCancel(ctx)
	defer stopCancelWatch()
	if err := c.driver.Walk(root, gosnmp.WalkFunc(fn)); err != nil {
		return fmt.Errorf("snmp walk %s %s: %w", c.target, root, err)
	}
	return nil
}

// WalkAllNext eh a forma materializada do Walk (GetNext). Usar quando o
// device nao suporta GetBulk pra esta tabela.
func (c *Client) WalkAllNext(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	err := c.Walk(ctx, root, func(p gosnmp.SnmpPDU) error {
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// WalkAll e a forma materializada do BulkWalk: acumula todas as PDUs num
// slice. Conveniencia para callers que nao precisam de streaming.
func (c *Client) WalkAll(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error) {
	var out []gosnmp.SnmpPDU
	err := c.BulkWalk(ctx, root, func(p gosnmp.SnmpPDU) error {
		out = append(out, p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Close fecha o socket UDP. Idempotente.
func (c *Client) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.driver == nil {
		return nil
	}
	return c.driver.Close()
}

// applyDeadline propaga o deadline do ctx (se houver) para o socket UDP.
// Sem deadline no ctx, cai no timeout configurado em Params.
func (c *Client) applyDeadline(ctx context.Context) {
	if c == nil || c.driver == nil || ctx == nil {
		return
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.driver.SetDeadline(dl)
		return
	}
	_ = c.driver.SetDeadline(time.Now().Add(c.timeout))
}

func (c *Client) watchCancel(ctx context.Context) func() {
	if c == nil || c.driver == nil || ctx == nil || ctx.Done() == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.driver.SetDeadline(time.Now())
		case <-done:
		}
	}()
	return func() { close(done) }
}

// PduFloat converte um SnmpPDU de tipo numerico em float64 para uso em metricas.
// Tipos nao numericos (OctetString, ObjectIdentifier, IPAddress) retornam
// ok=false — quem precisa do valor literal usa SnmpPDU.Value direto.
func PduFloat(p gosnmp.SnmpPDU) (float64, bool) {
	switch v := p.Value.(type) {
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

// splitHostPort divide "host[:port]" em (host, port, ok). Default port 161.
func splitHostPort(target string) (string, uint16, bool) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", 0, false
	}
	i := strings.LastIndex(t, ":")
	if i < 0 {
		return t, 161, true
	}
	host := t[:i]
	portStr := t[i+1:]
	if host == "" {
		return "", 0, false
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil || port == 0 {
		return "", 0, false
	}
	return host, port, true
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}
