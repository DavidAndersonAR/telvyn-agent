// snmptrap.go — B2: receptor SNMP Trap (UDP/162). O device AVISA na hora (link
// down, cold start, auth failure) em vez de esperar o próximo ciclo de poll. O
// listener parseia o trap (v1/v2c via gosnmp.TrapListener) e encaminha pro backend
// (/api/ingest/v1/snmptrap); o backend mapeia source_ip→host e classifica o OID.
//
// Gateado por ISPWATCH_SNMP_TRAPS_ENABLED=1 (estilo Datadog: 1 agente, cada
// capability liga/desliga). Bind em :162 exige root (o DaemonSet já roda privileged).

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ispwatch/collector/internal/otlp"
)

// snmpTrapOID.0 (SNMPv2-MIB) — varbind que carrega o OID do trap num trap v2c.
const snmpTrapOIDVar = "1.3.6.1.6.3.1.1.4.1.0"

// startSnmpTrapListener sobe o receptor UDP/162 e encaminha cada trap pro backend.
// Fail-soft: erro de bind só loga e desiste (não derruba o agente). Para no ctx.Done.
func startSnmpTrapListener(ctx context.Context, log *slog.Logger, exporter *otlp.IngestExporter) {
	addr := getenvOr("ISPWATCH_SNMP_TRAP_ADDR", "0.0.0.0:162")
	tl := gosnmp.NewTrapListener()
	tl.Params = gosnmp.Default // aceita community v1/v2c
	tl.OnNewTrap = func(pkt *gosnmp.SnmpPacket, u *net.UDPAddr) {
		trap := buildTrapPayload(pkt, u)
		if trap == nil {
			return
		}
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := exporter.PostSnmpTrap(cctx, trap); err != nil {
			log.Warn("snmp trap forward falhou", "err", err, "src", trap["source_ip"])
		}
	}
	go func() {
		<-ctx.Done()
		tl.Close()
	}()
	go func() {
		log.Info("snmp trap listener iniciado", "addr", addr)
		if err := tl.Listen(addr); err != nil {
			log.Warn("snmp trap listener parou", "err", err)
		}
	}()
}

// buildTrapPayload extrai {source_ip, trap_oid, varbinds} de um pacote de trap.
// v2c: o OID vem no varbind snmpTrapOID.0. v1: deriva de generic/specific-trap.
// Severity e mensagem ficam pro backend classificar (SnmpTrapIngestResource).
func buildTrapPayload(pkt *gosnmp.SnmpPacket, u *net.UDPAddr) map[string]any {
	if pkt == nil {
		return nil
	}
	sourceIP := ""
	if u != nil {
		sourceIP = u.IP.String()
	}
	trapOID := ""
	varbinds := make(map[string]string, len(pkt.Variables))
	for _, v := range pkt.Variables {
		oid := strings.TrimPrefix(v.Name, ".")
		val := pduToString(v)
		if oid == snmpTrapOIDVar || oid == "1.3.6.1.6.3.1.1.4.1" {
			trapOID = strings.TrimPrefix(val, ".")
			continue
		}
		varbinds[oid] = val
	}
	if trapOID == "" {
		trapOID = v1TrapOID(pkt)
	}
	if trapOID == "" {
		return nil
	}
	return map[string]any{
		"source_ip": sourceIP,
		"trap_oid":  trapOID,
		"varbinds":  varbinds,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// v1TrapOID mapeia um trap SNMPv1 (generic/specific) pro OID equivalente SNMPv2.
func v1TrapOID(pkt *gosnmp.SnmpPacket) string {
	if pkt.Version != gosnmp.Version1 {
		return ""
	}
	switch pkt.GenericTrap {
	case 0:
		return "1.3.6.1.6.3.1.1.5.1" // coldStart
	case 1:
		return "1.3.6.1.6.3.1.1.5.2" // warmStart
	case 2:
		return "1.3.6.1.6.3.1.1.5.3" // linkDown
	case 3:
		return "1.3.6.1.6.3.1.1.5.4" // linkUp
	case 4:
		return "1.3.6.1.6.3.1.1.5.5" // authenticationFailure
	case 5:
		return "1.3.6.1.6.3.1.1.5.6" // egpNeighborLoss
	case 6: // enterpriseSpecific → enterprise + ".0." + specific
		return strings.TrimPrefix(pkt.Enterprise, ".") + ".0." + strconv.Itoa(pkt.SpecificTrap)
	default:
		return ""
	}
}

func pduToString(v gosnmp.SnmpPDU) string {
	switch val := v.Value.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprintf("%d", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}
