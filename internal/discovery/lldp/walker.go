package lldp

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"google.golang.org/protobuf/types/known/structpb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// SnmpClient é a interface mínima que o walker precisa do cliente SNMP.
// Mantida pequena para facilitar mocks em teste.
type SnmpClient interface {
	Walk(ctx context.Context, root string) ([]gosnmp.SnmpPDU, error)
	Close()
	Host() string
}

// Walk corre 4 BulkWalks contra o target, correlaciona pelo sufixo
// (LocalPort, Index) e devolve um TopologyEdgeReport por vizinho.
//
// localHostId é o identificador desse equipamento no inventário do servidor —
// vai como TopologyEdgeReport.local_host_id. Quando vazio, cai pra Host()
// do client (o IP/hostname do target SNMP).
func Walk(ctx context.Context, c SnmpClient, localHostId string) ([]*collectorv1.TopologyEdgeReport, error) {
	if localHostId == "" {
		localHostId = c.Host()
	}

	// 1) Mapa LocalPortNum → nome legível ("Gi0/1") via lldpLocPortDesc
	locPorts, err := walkPortDesc(ctx, c)
	if err != nil {
		return nil, fmt.Errorf("lldp: locPortDesc: %w", err)
	}

	// 2) IF-MIB: speed por ifIndex; ifDescr fallback pra nome de iface local
	speeds, ifDescrs, err := walkIfTable(ctx, c)
	if err != nil {
		// IF-MIB indisponível não é fatal — speed=0, e cair no LocalPort do LLDP
		speeds = map[uint32]int32{}
		ifDescrs = map[uint32]string{}
	}

	// 3) Tabela remota — colunas que nos interessam
	chassisSubtype, _ := walkRemColumnInt(ctx, c, OIDLldpRemChassisIdSubtype)
	chassisId, _ := walkRemColumnRaw(ctx, c, OIDLldpRemChassisId)
	portSubtype, _ := walkRemColumnInt(ctx, c, OIDLldpRemPortIdSubtype)
	portId, _ := walkRemColumnRaw(ctx, c, OIDLldpRemPortId)
	portDesc, _ := walkRemColumn(ctx, c, OIDLldpRemPortDesc)
	sysName, _ := walkRemColumn(ctx, c, OIDLldpRemSysName)
	sysDesc, _ := walkRemColumn(ctx, c, OIDLldpRemSysDesc)

	// Agrupa por chave LocalPort/Index extraída do OID — toda coluna acima usa
	// a mesma chave; basta unir o conjunto de chaves vistas.
	keys := map[string]struct{}{}
	for k := range chassisId {
		keys[k] = struct{}{}
	}

	out := make([]*collectorv1.TopologyEdgeReport, 0, len(keys))
	for k := range keys {
		localPort, _ := splitNeighborKey(k)
		// Nome local: lldpLocPortDesc primeiro, IF-MIB ifDescr depois
		localIface := locPorts[localPort]
		if localIface == "" {
			localIface = ifDescrs[localPort]
		}
		if localIface == "" {
			localIface = fmt.Sprintf("port-%d", localPort)
		}

		speedMbps := int32(0)
		if v, ok := speeds[localPort]; ok {
			speedMbps = v
		}

		chassisSub := chassisSubtype[k]
		chassisRaw := chassisId[k]
		portSub := portSubtype[k]
		portRaw := portId[k]

		report := &collectorv1.TopologyEdgeReport{
			LocalHostId:            localHostId,
			LocalIface:             localIface,
			LocalIfaceSpeedMbps:    speedMbps,
			RemoteChassisIdSubtype: int32(chassisSub),
			RemoteChassisId:        formatId(chassisSub, chassisRaw),
			RemotePortIdSubtype:    int32(portSub),
			RemotePortId:           formatId(portSub, portRaw),
			RemotePortDesc:         portDesc[k],
			RemoteSysName:          sysName[k],
			RemoteSysDescr:         sysDesc[k],
			Layer:                  "L2",
			SourceProtocol:         "lldp",
			LinkType:               "ethernet",
		}
		// Raw debug payload — útil pra explicar matching falhado.
		raw, _ := structpb.NewStruct(map[string]any{
			"local_port_num":            float64(localPort),
			"chassis_id_subtype":        float64(chassisSub),
			"port_id_subtype":           float64(portSub),
			"chassis_id_hex":            hexBytes(chassisRaw),
			"port_id_hex":               hexBytes(portRaw),
		})
		if raw != nil {
			report.Raw = raw
		}
		out = append(out, report)
	}
	return out, nil
}

// walkPortDesc retorna {ifIndex local: nome da porta} via lldpLocPortDesc.
func walkPortDesc(ctx context.Context, c SnmpClient) (map[uint32]string, error) {
	pdus, err := c.Walk(ctx, OIDLldpLocPortDesc)
	if err != nil {
		return nil, err
	}
	out := make(map[uint32]string, len(pdus))
	for _, p := range pdus {
		idx, ok := lastUint32(p.Name)
		if !ok {
			continue
		}
		s := pduString(p)
		if s == "" {
			continue
		}
		out[idx] = s
	}
	return out, nil
}

// walkIfTable devolve (speed em Mbps, ifDescr) por ifIndex.
func walkIfTable(ctx context.Context, c SnmpClient) (map[uint32]int32, map[uint32]string, error) {
	speeds := map[uint32]int32{}
	ifDescrs := map[uint32]string{}

	if pdus, err := c.Walk(ctx, OIDIfSpeed); err == nil {
		for _, p := range pdus {
			idx, ok := lastUint32(p.Name)
			if !ok {
				continue
			}
			if v, ok := pduUint64(p); ok {
				// ifSpeed é bits/sec; convertemos pra Mbps
				speeds[idx] = int32(v / 1_000_000)
			}
		}
	}
	if pdus, err := c.Walk(ctx, OIDIfDescr); err == nil {
		for _, p := range pdus {
			idx, ok := lastUint32(p.Name)
			if !ok {
				continue
			}
			if s := pduString(p); s != "" {
				ifDescrs[idx] = s
			}
		}
	}
	return speeds, ifDescrs, nil
}

// walkRemColumn corre uma coluna de lldpRemTable e devolve o valor como
// string indexado pela chave (LocalPort.Index).
func walkRemColumn(ctx context.Context, c SnmpClient, oid string) (map[string]string, error) {
	pdus, err := c.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(pdus))
	for _, p := range pdus {
		key := neighborKey(p.Name)
		if key == "" {
			continue
		}
		out[key] = pduString(p)
	}
	return out, nil
}

// walkRemColumnInt devolve um int por entrada — para colunas tipo Integer
// (chassisIdSubtype / portIdSubtype).
func walkRemColumnInt(ctx context.Context, c SnmpClient, oid string) (map[string]int, error) {
	pdus, err := c.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int, len(pdus))
	for _, p := range pdus {
		key := neighborKey(p.Name)
		if key == "" {
			continue
		}
		switch v := p.Value.(type) {
		case int:
			out[key] = v
		case int64:
			out[key] = int(v)
		case uint:
			out[key] = int(v)
		case uint32:
			out[key] = int(v)
		}
	}
	return out, nil
}

// walkRemColumnRaw devolve os bytes brutos da coluna (necessário pra MAC/IP
// que vêm como OctetString não-printável).
func walkRemColumnRaw(ctx context.Context, c SnmpClient, oid string) (map[string][]byte, error) {
	pdus, err := c.Walk(ctx, oid)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(pdus))
	for _, p := range pdus {
		key := neighborKey(p.Name)
		if key == "" {
			continue
		}
		out[key] = pduBytes(p)
	}
	return out, nil
}

// neighborKey extrai (LocalPort.Index) do final do OID, descartando
// TimeMark. Ex: "1.0.8802.1.1.2.1.4.1.1.5.0.10.1" → "10.1".
func neighborKey(oid string) string {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) < 3 {
		return ""
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

func splitNeighborKey(k string) (uint32, uint32) {
	parts := strings.Split(k, ".")
	if len(parts) != 2 {
		return 0, 0
	}
	a, _ := strconv.ParseUint(parts[0], 10, 32)
	b, _ := strconv.ParseUint(parts[1], 10, 32)
	return uint32(a), uint32(b)
}

// lastUint32 extrai o último componente do OID como uint32.
func lastUint32(oid string) (uint32, bool) {
	parts := strings.Split(strings.TrimPrefix(oid, "."), ".")
	if len(parts) == 0 {
		return 0, false
	}
	v, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func pduString(p gosnmp.SnmpPDU) string {
	switch v := p.Value.(type) {
	case string:
		return strings.TrimRight(v, "\x00")
	case []byte:
		return strings.TrimRight(string(v), "\x00")
	default:
		return ""
	}
}

func pduBytes(p gosnmp.SnmpPDU) []byte {
	switch v := p.Value.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		return nil
	}
}

func pduUint64(p gosnmp.SnmpPDU) (uint64, bool) {
	switch v := p.Value.(type) {
	case uint:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	}
	return 0, false
}

// formatId pinta o ID per subtype: MAC vira "aa:bb:cc:dd:ee:ff", string fica
// como string, demais viram hex.
func formatId(subtype int, raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	switch subtype {
	case ChassisIdSubtypeMACAddress, PortIdSubtypeMACAddress:
		if len(raw) == 6 {
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
				raw[0], raw[1], raw[2], raw[3], raw[4], raw[5])
		}
	case ChassisIdSubtypeIfName, PortIdSubtypeIfName,
		ChassisIdSubtypeLocal,
		PortIdSubtypeIfAlias:
		if isPrintable(raw) {
			return strings.TrimRight(string(raw), "\x00")
		}
	}
	return hexBytes(raw)
}

func hexBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(parts, ":")
}

func isPrintable(b []byte) bool {
	for _, v := range b {
		if v < 0x20 || v > 0x7e {
			return v == 0 // permitir trailing NUL
		}
	}
	return true
}

// Garbage-collected tracking dos timeouts default
var _ = time.Second
