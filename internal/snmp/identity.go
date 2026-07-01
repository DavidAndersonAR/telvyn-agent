// identity.go — B3: coleta o INVENTÁRIO do device (sysDescr/sysObjectID/serial/
// modelo/versão/localização) via OIDs padrão (SNMPv2-MIB + ENTITY-MIB). O agente
// reporta pro backend (/api/ingest/v1/device-metadata → noc_device), que "acende"
// a aba Information do device. OIDs ausentes (device sem ENTITY-MIB) são ignorados.

package snmp

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// OIDs escalares de identidade → campo aceito pelo endpoint /device-metadata.
var identityOIDs = []struct{ oid, field string }{
	{"1.3.6.1.2.1.1.2.0", "sys_object_id"},            // sysObjectID
	{"1.3.6.1.2.1.1.6.0", "location"},                 // sysLocation
	{"1.3.6.1.2.1.47.1.1.1.1.13.1", "model"},          // entPhysicalModelName.1
	{"1.3.6.1.2.1.47.1.1.1.1.11.1", "serial_number"},  // entPhysicalSerialNum.1
}

var versionRe = regexp.MustCompile(`\d+\.\d+(?:\.\d+)*`)

// CollectIdentity lê os OIDs de identidade e devolve um mapa pronto pro
// /device-metadata (chaves: sys_object_id, location, model, serial_number,
// os_name, version). Nunca falha por OID ausente — só omite o campo.
func CollectIdentity(ctx context.Context, c *Client) (map[string]string, error) {
	out := make(map[string]string, 6)
	for _, it := range identityOIDs {
		if v, ok := getText(ctx, c, it.oid); ok {
			out[it.field] = v
		}
	}
	if s := out["sys_object_id"]; s != "" {
		out["sys_object_id"] = strings.TrimPrefix(s, ".")
	}
	if descr, ok := getText(ctx, c, "1.3.6.1.2.1.1.1.0"); ok { // sysDescr
		if osName, ver := parseSysDescr(descr); osName != "" {
			out["os_name"] = osName
			if ver != "" {
				out["version"] = ver
			}
		}
	}
	return out, nil
}

// getText faz um GET escalar e devolve o valor como string, ou (,"",false) se
// ausente/erro/exceção SNMP (NoSuchObject/Instance/EndOfMibView/Null).
func getText(ctx context.Context, c *Client, oid string) (string, bool) {
	pdus, err := c.Get(ctx, []string{oid})
	if err != nil || len(pdus) == 0 {
		return "", false
	}
	p := pdus[0]
	switch p.Type {
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView, gosnmp.Null:
		return "", false
	}
	var s string
	switch v := p.Value.(type) {
	case string:
		s = v
	case []byte:
		s = string(v)
	default:
		s = fmt.Sprintf("%v", v)
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

// parseSysDescr extrai os_name + version de sysDescr para as plataformas comuns
// (heurística leve — se não reconhece, devolve vazio e o backend só não preenche).
func parseSysDescr(descr string) (osName, version string) {
	d := strings.TrimSpace(descr)
	low := strings.ToLower(d)
	switch {
	case strings.Contains(low, "routeros"):
		osName = "RouterOS"
	case strings.Contains(low, "cisco ios") || strings.Contains(low, "cisco internetwork"):
		osName = "Cisco IOS"
	case strings.Contains(low, "nx-os"):
		osName = "Cisco NX-OS"
	case strings.Contains(low, "junos"):
		osName = "Junos"
	default:
		return "", ""
	}
	version = versionRe.FindString(d)
	return osName, version
}
