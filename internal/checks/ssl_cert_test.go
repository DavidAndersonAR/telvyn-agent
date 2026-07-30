package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// servidorTLS sobe um listener TLS com um certificado autoassinado que vence em
// `vence`. Devolve o endereco. Autoassinado de proposito: e o que prova que
// lemos a validade MESMO quando a cadeia nao e confiavel — o caso que o
// handshake normal do Go abortaria.
func servidorTLS(t *testing.T, vence time.Time) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gerar chave: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     vence,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("criar certificado: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// O handshake do crypto/tls e PREGUICOSO: so acontece no primeiro
			// Read/Write. Fechar apos o Accept faria o servidor nunca apresentar
			// o certificado, e o check veria "erro de conexao" — foi o que
			// aconteceu na primeira rodada deste teste.
			if tc, ok := conn.(*tls.Conn); ok {
				_ = tc.Handshake()
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

func rodar(t *testing.T, params map[string]string) map[string]float64 {
	t.Helper()
	cfg := &collectorv1.CheckConfig{
		CheckType: "ssl.cert",
		HostId:    "host-teste",
		Params:    params,
		Interval:  durationpb.New(time.Hour),
	}
	c, err := newSSLCertCheck(cfg)
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	ms, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	out := map[string]float64{}
	for _, m := range ms {
		out[m.GetMetricName()] = m.GetValue()
	}
	return out
}

func TestSSLCertLeValidadeDeCertificadoAutoassinado(t *testing.T) {
	addr := servidorTLS(t, time.Now().Add(30*24*time.Hour))
	got := rodar(t, map[string]string{"target": addr, "server_name": "localhost"})

	if got["ssl.error"] != 0 {
		t.Fatalf("esperava error=0, veio %v", got["ssl.error"])
	}
	// ~30 dias; tolerancia de 1 dia cobre o arredondamento da execucao.
	if d := got["ssl.days_to_expiry"]; d < 29 || d > 30.1 {
		t.Errorf("days_to_expiry: esperava ~30, veio %v", d)
	}
	// Autoassinado nao fecha em raiz do sistema — e essa a diferenca entre
	// "esta dentro da validade" e "o navegador aceita".
	if got["ssl.verified"] != 0 {
		t.Errorf("esperava verified=0 (autoassinado), veio %v", got["ssl.verified"])
	}
}

func TestSSLCertCertificadoVencidoDaDiasNEGATIVOSeNaoErro(t *testing.T) {
	// O caso que motivou o InsecureSkipVerify: vencido ainda precisa dizer
	// HA QUANTO venceu, em vez de virar "erro de conexao".
	addr := servidorTLS(t, time.Now().Add(-3*24*time.Hour))
	got := rodar(t, map[string]string{"target": addr, "server_name": "localhost"})

	if got["ssl.error"] != 0 {
		t.Fatalf("vencido não é erro de conexão; esperava error=0, veio %v", got["ssl.error"])
	}
	if d := got["ssl.days_to_expiry"]; d > -2.9 || d < -3.1 {
		t.Errorf("days_to_expiry: esperava ~-3, veio %v", d)
	}
}

func TestSSLCertPortaSemTLSViraErro(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	got := rodar(t, map[string]string{"target": ln.Addr().String(), "timeout_ms": "1500"})
	if got["ssl.error"] != 1 {
		t.Errorf("esperava error=1 em porta sem TLS, veio %v", got["ssl.error"])
	}
	// Sem certificado lido, nao inventamos validade: dia zero seria "vence
	// hoje" e dispararia alerta sozinho.
	if _, existe := got["ssl.days_to_expiry"]; existe {
		t.Errorf("não deveria emitir days_to_expiry sem certificado")
	}
}

func TestSSLCertAssumePorta443QuandoNaoInformada(t *testing.T) {
	c, err := newSSLCertCheck(&collectorv1.CheckConfig{
		CheckType: "ssl.cert",
		Params:    map[string]string{"target": "telvyn.example.com"},
	})
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	sc := c.(*sslCertCheck)
	if sc.target != "telvyn.example.com:443" {
		t.Errorf("target: esperava :443 acrescentado, veio %q", sc.target)
	}
	// SNI default = host do target, senão host virtual devolveria o
	// certificado errado e a verificação acusaria falso negativo.
	if sc.serverName != "telvyn.example.com" {
		t.Errorf("server_name: esperava host do target, veio %q", sc.serverName)
	}
}

func TestSSLCertUsaParamPortQuandoTargetVemSemPorta(t *testing.T) {
	// O formulário tem campo de porta separado (igual ao TCP). Se o agente
	// ignorasse esse param, alguém pediria 8443 e seria checado 443 — em
	// silêncio, que é o pior jeito de errar.
	c, err := newSSLCertCheck(&collectorv1.CheckConfig{
		CheckType: "ssl.cert",
		Params:    map[string]string{"target": "telvyn.example.com", "port": "8443"},
	})
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	if got := c.(*sslCertCheck).target; got != "telvyn.example.com:8443" {
		t.Errorf("target: esperava porta do param, veio %q", got)
	}
}

func TestSSLCertPortaNoTargetVencePortaNoParam(t *testing.T) {
	c, err := newSSLCertCheck(&collectorv1.CheckConfig{
		CheckType: "ssl.cert",
		Params:    map[string]string{"target": "telvyn.example.com:9443", "port": "8443"},
	})
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	if got := c.(*sslCertCheck).target; got != "telvyn.example.com:9443" {
		t.Errorf("target: o que está escrito no alvo manda, veio %q", got)
	}
}

func TestSSLCertExigeTarget(t *testing.T) {
	if _, err := newSSLCertCheck(&collectorv1.CheckConfig{CheckType: "ssl.cert"}); err == nil {
		t.Error("esperava erro sem target")
	}
}

func TestSSLCertIntervaloDefaultEUmaHora(t *testing.T) {
	c, err := newSSLCertCheck(&collectorv1.CheckConfig{
		CheckType: "ssl.cert",
		Params:    map[string]string{"target": "a.b:443"},
	})
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	if got := c.Interval(); got != time.Hour {
		t.Errorf("intervalo default: esperava 1h, veio %v", got)
	}
}
