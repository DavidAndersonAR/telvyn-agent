// ssl_cert.go — Check "ssl.cert": validade e confiabilidade do certificado TLS.
//
// Responde as duas perguntas que todo NOC faz: "quando vence?" e "o navegador
// aceita?". Sao coisas diferentes — certificado dentro da validade pode falhar
// por cadeia incompleta ou nome errado, e certificado vencido pode ter cadeia
// perfeita.
//
// DECISAO: o handshake roda com InsecureSkipVerify e a verificacao acontece
// DEPOIS, na mao. Se deixassemos o Go verificar durante o handshake, certificado
// vencido ou autoassinado abortaria a conexao com erro — e perderiamos justamente
// o numero que interessa, o "vence em N dias". Assim sempre lemos o certificado
// primeiro e julgamos em seguida.
//
// Metricas:
//   ssl.days_to_expiry - dias ate NotAfter; NEGATIVO quando ja venceu
//   ssl.verified       - 0/1 (1 = cadeia valida E nome casa; e o teste do navegador)
//   ssl.handshake_ms   - tempo do handshake TLS
//   ssl.error          - 0/1 (1 = nao deu pra conectar/ler certificado)
//
// Quando error=1 as outras nao sao emitidas: dia zero e "vence hoje", nao
// "nao sei" — emitir zero ali faria o alerta disparar por engano.
//
// Params:
//   target        - host:port ou host
//   port          - usado quando o target vem sem porta (default 443)
//   server_name   - SNI e nome verificado (opcional; default = host do target).
//                   Precisa existir separado porque host virtual serve N
//                   certificados no mesmo IP:porta.
//   timeout_ms    - default 5000 (handshake TLS e mais lento que TCP puro)
//   source_iface  - SO_BINDTODEVICE
//   source_ip     - net.Dialer.LocalAddr

package checks

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type sslCertCheck struct {
	id          string
	interval    time.Duration
	hostID      string
	target      string // sempre host:port
	serverName  string
	timeout     time.Duration
	sourceIface string
	sourceIP    string
	staticTags  map[string]string
}

func newSSLCertCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return nil, fmt.Errorf("ssl.cert: missing param 'target'")
	}
	// Porta pode vir DENTRO do target ("host:8443") ou no param 'port' — o
	// formulario usa campo separado, igual ao check de TCP. Sem nenhum dos dois,
	// 443: quem digita "meusite.com.br" quer HTTPS.
	if _, _, err := net.SplitHostPort(target); err != nil {
		port := strings.TrimSpace(params["port"])
		if port == "" {
			port = "443"
		}
		target = net.JoinHostPort(target, port)
	}

	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("ssl.cert: target inválido %q: %w", target, err)
	}

	serverName := strings.TrimSpace(params["server_name"])
	if serverName == "" {
		serverName = host
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		// Certificado muda de mes em mes, nao de minuto em minuto. 1h e
		// suficiente e evita handshake TLS a cada 30s de graca.
		interval = time.Hour
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "ssl.cert-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &sslCertCheck{
		id:          id,
		interval:    interval,
		hostID:      cfg.GetHostId(),
		target:      target,
		serverName:  serverName,
		timeout:     parseTimeoutMs(params, 5000),
		sourceIface: params["source_iface"],
		sourceIP:    params["source_ip"],
		staticTags:  tags,
	}, nil
}

func (c *sslCertCheck) ID() string              { return c.id }
func (c *sslCertCheck) Interval() time.Duration { return c.interval }
func (c *sslCertCheck) Tags() map[string]string { return c.staticTags }

func (c *sslCertCheck) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	dialer := newBindingDialer(c.sourceIface, c.sourceIP, c.timeout)

	dialCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	now := timestamppb.Now()

	raw, err := dialer.DialContext(dialCtx, "tcp", c.target)
	if err != nil {
		return []*collectorv1.Metric{c.metric(now, "ssl.error", 1)}, nil
	}
	defer func() { _ = raw.Close() }()

	// InsecureSkipVerify de proposito — ver a DECISAO no topo do arquivo.
	conn := tls.Client(raw, &tls.Config{
		ServerName:         c.serverName,
		InsecureSkipVerify: true, //nolint:gosec // a verificacao e feita abaixo, na mao
	})

	start := time.Now()
	if err := conn.HandshakeContext(dialCtx); err != nil {
		// Sem handshake nao existe certificado pra ler: servidor sem TLS na
		// porta, ou protocolo incompativel.
		return []*collectorv1.Metric{c.metric(now, "ssl.error", 1)}, nil
	}
	elapsed := time.Since(start)

	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		return []*collectorv1.Metric{c.metric(now, "ssl.error", 1)}, nil
	}
	leaf := chain[0]

	verified := 0.0
	if certTrusted(chain, c.serverName) {
		verified = 1
	}

	return []*collectorv1.Metric{
		c.metric(now, "ssl.days_to_expiry", daysUntil(leaf.NotAfter, time.Now())),
		c.metric(now, "ssl.verified", verified),
		c.metric(now, "ssl.handshake_ms", float64(elapsed)/float64(time.Millisecond)),
		c.metric(now, "ssl.error", 0),
	}, nil
}

// daysUntil devolve dias fracionados ate `deadline`. Negativo = ja venceu, e o
// sinal importa: "-3" conta uma historia diferente de "3".
func daysUntil(deadline, from time.Time) float64 {
	return deadline.Sub(from).Hours() / 24
}

// certTrusted repete o julgamento do navegador: cadeia que fecha numa raiz do
// sistema E nome que casa. Os intermediarios vem do proprio servidor (e o que o
// navegador usa); raiz sai do pool do SO.
func certTrusted(chain []*x509.Certificate, serverName string) bool {
	if len(chain) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err := chain[0].Verify(x509.VerifyOptions{
		DNSName:       serverName,
		Intermediates: intermediates,
	})
	return err == nil
}

func (c *sslCertCheck) metric(t *timestamppb.Timestamp, name string, value float64) *collectorv1.Metric {
	tags := make(map[string]string, len(c.staticTags)+2)
	for k, v := range c.staticTags {
		tags[k] = v
	}
	tags["target"] = c.target
	if c.serverName != "" {
		tags["server_name"] = c.serverName
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     c.hostID,
		MetricName: name,
		Value:      value,
		Tags:       tags,
		Source:     "ssl",
	}
}

func init() {
	Default.Register("ssl.cert", newSSLCertCheck)
}
