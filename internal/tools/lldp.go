package tools

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"

	"github.com/ispwatch/collector/internal/snmp"
)

// LldpDiscover walks the LLDP-MIB (RFC 2922 / IEEE 802.1AB) on the target and
// returns the table of remote neighbors visible to it. Designed for the
// "Importar via LLDP" UX in the topology editor: pick a seed host, get the
// list of switches/routers it sees directly, add them to the canvas.
//
// Why LLDP-MIB instead of vendor-specific shells (mikrotik.discover_topology):
//
//   - Universal — same OIDs in Cisco, Juniper, Mikrotik, Aruba, HPE, Fortinet
//   - SNMP read-only (lower-risk credential vs SSH shell access)
//   - Already integrated — collector has snmp.Client + 176 vendor profiles
//   - Faster — single walk vs SSH dial + N commands
//
// args (envelope shared with snmp.get/snmp.walk via paramsFromArgs):
//
//	target           string   required  "host" or "host:port" (default :161)
//	community        string   required v2c  read community
//	version          string   "v2c" (default) | "v3"
//	v3_user, v3_auth_*, v3_priv_*, v3_context — v3 fields when version=v3
//	timeout_seconds  number   optional, default 5
//
// Returns:
//
//	result["neighbors"] = [{
//	    local_port_num:    number,   // lldpRemLocalPortNum (interface ifIndex-ish)
//	    local_port_id:     string,   // lldpLocPortId rendered (when port table walked)
//	    local_port_desc:   string,   // lldpLocPortDesc when available
//	    chassis_id_subtype: number,
//	    chassis_id:        string,   // MAC (4) → "aa:bb:..", netAddr (5) → "1.2.3.4", else hex/string
//	    port_id_subtype:   number,
//	    port_id:           string,
//	    port_desc:         string,
//	    sys_name:          string,
//	    sys_desc:          string,
//	    mgmt_ip:           string,   // best-effort from lldpRemManAddrTable index
//	}]
//	result["count"] = number
//
// Failure modes:
//   - LLDP not enabled on device → empty neighbors (not an error)
//   - SNMP creds wrong/unreachable → SNMP-layer error returned as-is
type LldpDiscover struct{}

func (LldpDiscover) Name() string { return "lldp.discover" }

const (
	lldpRemTableRoot    = "1.0.8802.1.1.2.1.4.1.1"
	lldpRemManAddrEntry = "1.0.8802.1.1.2.1.4.2.1"
	lldpLocPortEntry    = "1.0.8802.1.1.2.1.3.7.1"
	lldpLocChassisId    = "1.0.8802.1.1.2.1.3.2.0"
	lldpLocSysName      = "1.0.8802.1.1.2.1.3.3.0"
	ifPhysAddress       = "1.3.6.1.2.1.2.2.1.6"
	ifDescr             = "1.3.6.1.2.1.2.2.1.2"
	ifName              = "1.3.6.1.2.1.31.1.1.1.1"
	ipAddrEntIfIndex    = "1.3.6.1.2.1.4.20.1.2"        // index = IPv4 addr; value = ifIndex
	ipNetToMediaTable   = "1.3.6.1.2.1.4.22.1"          // ARP (legacy, ubiquitous)
	ipNetToMediaPhys    = "1.3.6.1.2.1.4.22.1.2"        // col 2 = MAC
	ipNetToMediaType    = "1.3.6.1.2.1.4.22.1.4"        // 1=other 2=invalid 3=dynamic 4=static
)

type lldpNeighbor struct {
	localPort        int
	chassisIdSubtype int
	chassisId        string
	portIdSubtype    int
	portId           string
	portDesc         string
	sysName          string
	sysDesc          string
	mgmtIp           string
	source           string // "lldp" | "arp"
	localIfaceLabel  string // ifDescr/ifName when source=arp
}

func (LldpDiscover) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	p, err := paramsFromArgs(args)
	if err != nil {
		return nil, err
	}
	c, err := snmp.NewClient(p)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	// 0) Local identity. RouterOS (and others) echo their own VLANs/bondings
	//    back as "neighbors" via internal LLDP; without this filter the user
	//    sees the seed device's own interface list instead of real peers.
	localChassis := ""
	localSysName := ""
	localMacs := map[string]bool{} // lowercase aa:bb:cc:dd:ee:ff
	localIps := map[string]bool{}  // dotted IPv4 strings
	ifIndexToLabel := map[int]string{}
	if pdus, err := c.Get(ctx, []string{lldpLocChassisId, lldpLocSysName}); err == nil {
		for _, pdu := range pdus {
			oid := strings.TrimPrefix(pdu.Name, ".")
			switch oid {
			case lldpLocChassisId:
				localChassis = strings.ToLower(renderLldpId(pdu, 4, true))
			case lldpLocSysName:
				localSysName = strings.ToLower(strings.TrimSpace(pduString(pdu)))
			}
		}
	}
	if macPdus, err := c.WalkAllNext(ctx, ifPhysAddress); err == nil {
		for _, pdu := range macPdus {
			b, ok := pdu.Value.([]byte)
			if !ok || len(b) != 6 {
				continue
			}
			localMacs[strings.ToLower(formatMac(b))] = true
		}
	}
	if localChassis != "" {
		localMacs[localChassis] = true
	}
	// Local IPv4 addresses (used to skip "neighbors" that are actually our own).
	if ipPdus, err := c.WalkAllNext(ctx, ipAddrEntIfIndex); err == nil {
		for _, pdu := range ipPdus {
			oid := strings.TrimPrefix(pdu.Name, ".")
			// .1.3.6.1.2.1.4.20.1.2.<IPv4> — last 4 octets are the address
			parts := strings.Split(oid, ".")
			if len(parts) < 4 {
				continue
			}
			ip := strings.Join(parts[len(parts)-4:], ".")
			localIps[ip] = true
		}
	}
	// ifIndex → friendly name. Prefer ifName (newer, gives "ether1" instead of
	// "ether1-Uplink-Cliente"), fall back to ifDescr.
	if pdus, err := c.WalkAllNext(ctx, ifName); err == nil {
		for _, pdu := range pdus {
			oid := strings.TrimPrefix(pdu.Name, ".")
			ix, _ := strconv.Atoi(oid[len(ifName)+1:])
			if ix > 0 {
				ifIndexToLabel[ix] = pduString(pdu)
			}
		}
	}
	if len(ifIndexToLabel) == 0 {
		if pdus, err := c.WalkAllNext(ctx, ifDescr); err == nil {
			for _, pdu := range pdus {
				oid := strings.TrimPrefix(pdu.Name, ".")
				ix, _ := strconv.Atoi(oid[len(ifDescr)+1:])
				if ix > 0 {
					ifIndexToLabel[ix] = pduString(pdu)
				}
			}
		}
	}

	isLocal := func(chassis, sysName string) bool {
		c := strings.ToLower(strings.TrimSpace(chassis))
		s := strings.ToLower(strings.TrimSpace(sysName))
		if c != "" && localMacs[c] {
			return true
		}
		if s != "" && localSysName != "" && s == localSysName {
			return true
		}
		return false
	}

	neighbors := map[string]*lldpNeighbor{}

	// 1) lldpRemTable: chassisId, portId, sysName, sysDesc per neighbor.
	//    Uses GetNext (Walk) — some v2c devices (Mikrotik RouterOS observed)
	//    reject GetBulk on the LLDP rem table even though GetBulk works for
	//    other tables on the same device.
	remPdus, err := c.WalkAllNext(ctx, lldpRemTableRoot)
	if err != nil {
		return nil, fmt.Errorf("lldp: walk remTable: %w", err)
	}
	for _, pdu := range remPdus {
		col, idx, ok := splitLldpRemOid(pdu.Name, lldpRemTableRoot)
		if !ok {
			continue
		}
		// idx = timeMark.localPort.remIndex
		idxParts := strings.Split(idx, ".")
		if len(idxParts) < 3 {
			continue
		}
		key := strings.Join(idxParts[:3], ".")
		n := neighbors[key]
		if n == nil {
			lp, _ := strconv.Atoi(idxParts[1])
			n = &lldpNeighbor{localPort: lp}
			neighbors[key] = n
		}
		switch col {
		case "4":
			if v, ok := pduInt(pdu); ok {
				n.chassisIdSubtype = v
			}
		case "5":
			n.chassisId = renderLldpId(pdu, n.chassisIdSubtype, true)
		case "6":
			if v, ok := pduInt(pdu); ok {
				n.portIdSubtype = v
			}
		case "7":
			n.portId = renderLldpId(pdu, n.portIdSubtype, false)
		case "8":
			n.portDesc = pduString(pdu)
		case "9":
			n.sysName = pduString(pdu)
		case "10":
			n.sysDesc = pduString(pdu)
		}
	}

	// 2) lldpRemManAddrTable: mgmt IP per neighbor (best-effort)
	// Index after the column = timeMark.localPort.remIndex.addrSubtype.addrLen.<addrBytes>
	manPdus, manErr := c.WalkAllNext(ctx, lldpRemManAddrEntry)
	if manErr == nil {
		for _, pdu := range manPdus {
			col, idx, ok := splitLldpRemOid(pdu.Name, lldpRemManAddrEntry)
			if !ok {
				continue
			}
			// Only need to derive the address once per neighbor; lock on col=1
			// (lldpRemManAddrSubtype) which is always present per entry.
			if col != "1" {
				continue
			}
			idxParts := strings.Split(idx, ".")
			if len(idxParts) < 5 {
				continue
			}
			key := strings.Join(idxParts[:3], ".")
			n := neighbors[key]
			if n == nil || n.mgmtIp != "" {
				continue
			}
			addrSubtype, _ := strconv.Atoi(idxParts[3])
			addrLen, _ := strconv.Atoi(idxParts[4])
			if addrLen <= 0 || len(idxParts) < 5+addrLen {
				continue
			}
			n.mgmtIp = decodeIpFromOidBytes(addrSubtype, idxParts[5:5+addrLen])
		}
	}

	// 3) lldpLocPortTable: map localPortNum → friendly local port name. Best-effort.
	localPortLabels := map[int]struct{ id, desc string }{}
	locPdus, locErr := c.WalkAllNext(ctx, lldpLocPortEntry)
	if locErr == nil {
		for _, pdu := range locPdus {
			col, idx, ok := splitLldpRemOid(pdu.Name, lldpLocPortEntry)
			if !ok {
				continue
			}
			portNum, err := strconv.Atoi(idx)
			if err != nil {
				continue
			}
			entry := localPortLabels[portNum]
			switch col {
			case "3":
				entry.id = pduString(pdu)
			case "4":
				entry.desc = pduString(pdu)
			}
			localPortLabels[portNum] = entry
		}
	}

	// 4) Tag LLDP-sourced neighbors and walk ARP for the rest.
	for _, n := range neighbors {
		n.source = "lldp"
	}

	// 5) ARP table (ipNetToMediaTable): catches OLTs, servers, CPEs that don't
	//    speak LLDP. Each ARP entry is "I saw <mac> respond at <ip> on <ifIndex>".
	//    Index = ifIndex.IPv4 (5 segments: ix.a.b.c.d).
	arpDropped := 0
	type arpKey struct{ mac string }
	arpAdded := map[arpKey]bool{}
	type arpRow struct {
		ifIndex int
		ip      string
		mac     string
		typ     int
	}
	arpRows := map[string]*arpRow{}
	arpPdus, _ := c.WalkAllNext(ctx, ipNetToMediaTable)
	for _, pdu := range arpPdus {
		oid := strings.TrimPrefix(pdu.Name, ".")
		// .1.3.6.1.2.1.4.22.1.<col>.<ifIndex>.<a>.<b>.<c>.<d>
		suffix := strings.TrimPrefix(oid, ipNetToMediaTable+".")
		parts := strings.Split(suffix, ".")
		if len(parts) < 6 {
			continue
		}
		col := parts[0]
		ifIx, _ := strconv.Atoi(parts[1])
		ip := strings.Join(parts[2:6], ".")
		rowKey := fmt.Sprintf("%d|%s", ifIx, ip)
		row := arpRows[rowKey]
		if row == nil {
			row = &arpRow{ifIndex: ifIx, ip: ip}
			arpRows[rowKey] = row
		}
		switch col {
		case "2":
			if b, ok := pdu.Value.([]byte); ok && len(b) == 6 {
				row.mac = strings.ToLower(formatMac(b))
			}
		case "4":
			if v, ok := pduInt(pdu); ok {
				row.typ = v
			}
		}
	}
	for _, row := range arpRows {
		if row.mac == "" {
			arpDropped++
			continue
		}
		// type 2 = invalid (incomplete ARP)
		if row.typ == 2 {
			arpDropped++
			continue
		}
		// Skip local: own MAC OR own IP
		if localMacs[row.mac] || localIps[row.ip] || isMulticastOrBroadcast(row.ip) {
			arpDropped++
			continue
		}
		if arpAdded[arpKey{row.mac}] {
			arpDropped++
			continue
		}
		arpAdded[arpKey{row.mac}] = true
		key := "arp:" + row.mac
		// Skip if LLDP already covered this MAC (LLDP entry wins — it has sysName).
		alreadyLldp := false
		for _, ln := range neighbors {
			if strings.ToLower(ln.chassisId) == row.mac {
				alreadyLldp = true
				break
			}
		}
		if alreadyLldp {
			arpDropped++
			continue
		}
		neighbors[key] = &lldpNeighbor{
			localPort:        row.ifIndex,
			chassisIdSubtype: 4, // MAC
			chassisId:        row.mac,
			portIdSubtype:    5, // network address
			portId:           row.ip,
			portDesc:         "",
			sysName:          "", // ARP doesn't carry sysName
			sysDesc:          "ARP-discovered",
			mgmtIp:           row.ip,
			source:           "arp",
			localIfaceLabel:  ifIndexToLabel[row.ifIndex],
		}
	}

	// Filter self-loops + dedup by remote chassis_id (1 icon per remote device).
	// Skipped count is reported so the operator can see why few neighbors came
	// back vs the raw count of LLDP-MIB rows.
	type bucket struct {
		n             *lldpNeighbor
		localPortIds  []string
		localPortDescs []string
	}
	byChassis := map[string]*bucket{}
	droppedSelfLoops := 0
	for _, n := range neighbors {
		if n.chassisId == "" && n.sysName == "" {
			continue
		}
		if isLocal(n.chassisId, n.sysName) {
			droppedSelfLoops++
			continue
		}
		key := strings.ToLower(n.chassisId)
		if key == "" {
			key = strings.ToLower(n.sysName)
		}
		b, ok := byChassis[key]
		if !ok {
			b = &bucket{n: n}
			byChassis[key] = b
		}
		if lbl, ok := localPortLabels[n.localPort]; ok {
			if lbl.id != "" {
				b.localPortIds = append(b.localPortIds, lbl.id)
			}
			if lbl.desc != "" {
				b.localPortDescs = append(b.localPortDescs, lbl.desc)
			}
		}
	}

	// local_host_id stamps each topology edge so the server resolves the near
	// side against its inventory (noc_host.uuid). Server-driven scheduled jobs
	// pass it explicitly; manual/UI callers fall back to the device's own
	// advertised identity (edges with an empty id are dropped downstream).
	effectiveLocalId, _ := args["local_host_id"].(string)
	if effectiveLocalId == "" {
		effectiveLocalId = localSysName
	}
	if effectiveLocalId == "" {
		effectiveLocalId = localChassis
	}

	out := make([]any, 0, len(byChassis))
	topoEdges := make([]map[string]any, 0, len(byChassis))
	for _, b := range byChassis {
		n := b.n
		localId := strings.Join(uniqueStrings(b.localPortIds), ", ")
		if localId == "" && n.localIfaceLabel != "" {
			localId = n.localIfaceLabel
		}
		out = append(out, map[string]any{
			"local_port_num":     float64(n.localPort),
			"local_port_id":      localId,
			"local_port_desc":    strings.Join(uniqueStrings(b.localPortDescs), ", "),
			"chassis_id":         n.chassisId,
			"chassis_id_subtype": float64(n.chassisIdSubtype),
			"port_id":            n.portId,
			"port_id_subtype":    float64(n.portIdSubtype),
			"port_desc":          n.portDesc,
			"sys_name":           n.sysName,
			"sys_desc":           n.sysDesc,
			"mgmt_ip":            n.mgmtIp,
			"source":             n.source,
		})

		// Local iface label for the topology edge, aligned with the interface
		// registry (which keys on ifName, OID 31.1.1.1.1). Prefer lldpLocPortDesc
		// (the spec-correct local port name, == ifName on RouterOS), then ifName
		// via ifIndex, then the LLDP local port id (often a MAC) as last resort —
		// so the Sentinela consumer can join "interface X down" → edge by name.
		localIface := strings.Join(uniqueStrings(b.localPortDescs), ", ")
		if localIface == "" {
			localIface = ifIndexToLabel[n.localPort]
		}
		if localIface == "" {
			localIface = localId
		}

		// Parallel edge shape for the topology ingest path: the scheduler reads
		// result["topology_edges"] → ReportTopology → TopologyIngestService.
		if effectiveLocalId != "" {
			topoEdges = append(topoEdges, map[string]any{
				"local_host_id":             effectiveLocalId,
				"local_iface":               localIface,
				"remote_chassis_id":         n.chassisId,
				"remote_chassis_id_subtype": float64(n.chassisIdSubtype),
				"remote_port_id":            n.portId,
				"remote_port_id_subtype":    float64(n.portIdSubtype),
				"remote_port_desc":          n.portDesc,
				"remote_sys_name":           n.sysName,
				"remote_sys_descr":          n.sysDesc,
				"layer":                     "L2",
				"source_protocol":           "lldp",
			})
		}
	}
	return map[string]any{
		"neighbors":           out,
		"topology_edges":      topoEdges,
		"count":               float64(len(out)),
		"raw_entries":         float64(len(neighbors)),
		"dropped_self_loops":  float64(droppedSelfLoops),
		"arp_dropped":         float64(arpDropped),
		"local_sys_name":      localSysName,
		"local_chassis_id":    localChassis,
	}, nil
}

func isMulticastOrBroadcast(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	first, _ := strconv.Atoi(parts[0])
	if first >= 224 { // 224.0.0.0/4 + 240.0.0.0/4 reserved
		return true
	}
	if ip == "255.255.255.255" || ip == "0.0.0.0" {
		return true
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] || s == "" {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// splitLldpRemOid breaks an OID like ".1.0.8802.1.1.2.1.4.1.1.<col>.<idx...>"
// into (col, "idx.parts.joined", true). Returns ok=false when oid doesn't
// belong under root or is missing the column segment.
func splitLldpRemOid(oid, root string) (string, string, bool) {
	o := strings.TrimPrefix(oid, ".")
	o = strings.TrimPrefix(o, root+".")
	if o == oid && !strings.HasPrefix(oid, ".") {
		// no change → didn't strip anything → not under root
		return "", "", false
	}
	parts := strings.SplitN(o, ".", 2)
	if len(parts) < 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// renderLldpId renders chassisId/portId per LLDP-MIB subtype semantics.
//
//	chassis: 1=entChassis, 2=ifAlias, 3=portComponent, 4=MAC, 5=netAddr, 6=ifName, 7=local
//	port:    1=ifAlias, 2=portComponent, 3=MAC, 4=netAddr, 5=ifName, 6=agentCircuitId, 7=local
//
// For MAC subtypes, emits canonical "aa:bb:cc:dd:ee:ff". For network address
// subtypes, first byte is family (1=IPv4, 2=IPv6). Everything else falls back
// to printable string when possible, hex otherwise.
func renderLldpId(pdu gosnmp.SnmpPDU, subtype int, isChassis bool) string {
	b, ok := pdu.Value.([]byte)
	if !ok {
		return pduString(pdu)
	}
	macSubtype := 3
	netAddrSubtype := 4
	if isChassis {
		macSubtype = 4
		netAddrSubtype = 5
	}
	if subtype == macSubtype && len(b) == 6 {
		return formatMac(b)
	}
	if subtype == netAddrSubtype && len(b) >= 5 {
		switch b[0] {
		case 1: // IPv4
			if len(b) == 5 {
				return fmt.Sprintf("%d.%d.%d.%d", b[1], b[2], b[3], b[4])
			}
		case 2: // IPv6
			if len(b) == 17 {
				parts := make([]string, 8)
				for i := 0; i < 8; i++ {
					parts[i] = fmt.Sprintf("%x", uint16(b[1+i*2])<<8|uint16(b[2+i*2]))
				}
				return strings.Join(parts, ":")
			}
		}
	}
	s := strings.TrimRight(string(b), "\x00")
	if isPrintableLldp(s) {
		return s
	}
	return hex.EncodeToString(b)
}

func formatMac(b []byte) string {
	out := make([]string, len(b))
	for i, v := range b {
		out[i] = fmt.Sprintf("%02x", v)
	}
	return strings.Join(out, ":")
}

func isPrintableLldp(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
		if r > 0x7e {
			return false
		}
	}
	return true
}

func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case []byte:
		return strings.TrimRight(string(v), "\x00")
	case string:
		return v
	}
	return fmt.Sprintf("%v", pdu.Value)
}

func pduInt(pdu gosnmp.SnmpPDU) (int, bool) {
	switch v := pdu.Value.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	}
	return 0, false
}

// decodeIpFromOidBytes converts the address bytes embedded in the LLDP-MIB
// management address table index into a printable IP. Subtypes follow the
// InetAddress conventions: 1=IPv4 (4 bytes), 2=IPv6 (16 bytes).
func decodeIpFromOidBytes(addrSubtype int, oidParts []string) string {
	switch addrSubtype {
	case 1:
		if len(oidParts) == 4 {
			return strings.Join(oidParts, ".")
		}
	case 2:
		if len(oidParts) == 16 {
			parts := make([]string, 8)
			for i := 0; i < 8; i++ {
				a, _ := strconv.Atoi(oidParts[i*2])
				b, _ := strconv.Atoi(oidParts[i*2+1])
				parts[i] = fmt.Sprintf("%x", (a<<8)|b)
			}
			return strings.Join(parts, ":")
		}
	}
	return ""
}
