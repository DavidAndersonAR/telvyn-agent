package checks

import (
	"net"
	"testing"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

func ipAddrs(vals ...string) []net.IPAddr {
	out := make([]net.IPAddr, 0, len(vals))
	for _, v := range vals {
		out = append(out, net.IPAddr{IP: net.ParseIP(v)})
	}
	return out
}

func TestDNSMatchExigeTodosOsIPsNaLista(t *testing.T) {
	esperado := []string{"203.0.113.10", "203.0.113.11"}

	casos := []struct {
		nome    string
		got     []net.IPAddr
		casa    bool
		porqueP string
	}{
		{"resposta exata", ipAddrs("203.0.113.10"), true, ""},
		{"as duas da lista", ipAddrs("203.0.113.10", "203.0.113.11"), true, ""},
		{"ordem invertida", ipAddrs("203.0.113.11", "203.0.113.10"), true, "ordem de resposta DNS não é estável"},
		{"ip fora da lista", ipAddrs("198.51.100.7"), false, ""},
		{"legítimo + intruso", ipAddrs("203.0.113.10", "198.51.100.7"), false,
			"é o caso do sequestro: o IP certo continua na resposta, o falso entra ao lado"},
		{"resposta vazia", nil, false, "sem resposta não há como afirmar que casou"},
	}

	for _, c := range casos {
		if got := ipsAllExpected(c.got, esperado); got != c.casa {
			t.Errorf("%s: esperava %v, veio %v %s", c.nome, c.casa, got, c.porqueP)
		}
	}
}

func TestDNSMatchCompararPorEnderecoNaoPorTexto(t *testing.T) {
	// Mesmo endereço, grafias diferentes: IPv4 mapeado em IPv6 e IPv6 abreviado.
	if !ipsAllExpected(ipAddrs("::ffff:203.0.113.10"), []string{"203.0.113.10"}) {
		t.Error("IPv4 mapeado em IPv6 deveria casar com o IPv4")
	}
	if !ipsAllExpected(ipAddrs("2001:db8::1"), []string{"2001:0db8:0000:0000:0000:0000:0000:0001"}) {
		t.Error("IPv6 abreviado deveria casar com a forma longa")
	}
}

func TestDNSMatchListaInvalidaNaoAfirmaQueCasou(t *testing.T) {
	// Campo digitado errado ("meusite.com" no lugar de um IP) não pode virar
	// "casou" — isso esconderia o problema em vez de mostrar.
	if ipsAllExpected(ipAddrs("203.0.113.10"), []string{"meusite.com"}) {
		t.Error("lista sem nenhum IP válido não deveria casar")
	}
}

func TestParseExpectedIPsToleraEspacoEVirgulaSobrando(t *testing.T) {
	got := parseExpectedIPs(" 203.0.113.10 , ,203.0.113.11,")
	if len(got) != 2 || got[0] != "203.0.113.10" || got[1] != "203.0.113.11" {
		t.Errorf("parse: veio %#v", got)
	}
	if len(parseExpectedIPs("")) != 0 {
		t.Error("vazio deveria virar lista vazia")
	}
}

func TestDNSSemExpectedIPsNaoMudaComportamento(t *testing.T) {
	// Regressão: config existente (sem o param novo) não pode passar a emitir
	// métrica nova — quem já tem alerta montado veria série aparecer do nada.
	c, err := newDNSLookupCheck(&collectorv1.CheckConfig{
		CheckType: "dns.lookup",
		Params:    map[string]string{"target": "exemplo.com.br"},
	})
	if err != nil {
		t.Fatalf("criar check: %v", err)
	}
	if n := len(c.(*dnsLookupCheck).expectedIPs); n != 0 {
		t.Errorf("expectedIPs deveria estar vazio, veio %d", n)
	}
}
