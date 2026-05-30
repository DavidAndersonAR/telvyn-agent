// source_binding.go — helpers compartilhados pelos probes de link_probe
// (http.get, dns.lookup, tcp.connect, http.throughput, mtr).
//
// O collector roda atras de um roteador com multiplos uplinks. Para que
// um probe meca o link "Vivo" e nao a rota default, ele precisa sair
// pela NIC certa. Duas opcoes:
//   - source_iface: SO_BINDTODEVICE no socket (Linux). Exige CAP_NET_RAW
//     ou CAP_NET_ADMIN, ja temos via systemd unit.
//   - source_ip: net.Dialer.LocalAddr = ip. Funciona sem capabilities;
//     so e suficiente quando cada IP local corresponde a uma rota distinta.
//
// Quando ambos vem populados, source_iface tem prioridade (mais robusto
// vs. mudancas de IP dinamicas no DHCP do uplink).

package checks

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// newBindingDialer monta um net.Dialer com source binding aplicado quando
// os parametros nao estao vazios. timeout=0 deixa o caller controlar via
// contexto da chamada (DialContext respeita ctx.Done()).
func newBindingDialer(sourceIface, sourceIP string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if sourceIP != "" {
		if ip := net.ParseIP(sourceIP); ip != nil {
			// Porta 0 -> kernel escolhe. Net dispara erro se IP nao bate
			// com nenhuma rota local — bug-de-config explicito, melhor que
			// silenciosamente sair pelo default.
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	if sourceIface != "" {
		iface := sourceIface
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var ferr error
			err := c.Control(func(fd uintptr) {
				ferr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
			})
			if err != nil {
				return fmt.Errorf("rawconn control: %w", err)
			}
			if ferr != nil {
				return fmt.Errorf("setsockopt SO_BINDTODEVICE(%q): %w", iface, ferr)
			}
			return nil
		}
	}
	return d
}

// parseTimeoutMs converte param string em time.Duration, com default e
// minimo configuraveis. Util pra todos os probes (todos aceitam timeout_ms).
func parseTimeoutMs(params map[string]string, defaultMs int) time.Duration {
	v := parseIntParam(params, "timeout_ms", defaultMs)
	if v <= 0 {
		v = defaultMs
	}
	return time.Duration(v) * time.Millisecond
}
