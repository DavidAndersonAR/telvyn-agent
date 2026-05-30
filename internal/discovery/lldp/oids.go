// Package lldp implements LLDP/CDP topology discovery via SNMP.
//
// Walks the LLDP-MIB (IEEE 802.1AB) on a target switch/router and produces
// TopologyEdgeReport messages suitable for the central server's
// ReportTopology RPC.
//
// Why no CDP yet: LLDP covers ~all enterprise gear shipped after 2008 (Cisco
// included). CDP (Cisco-proprietary) adds value only on legacy-Cisco-only
// fabrics — when that lands the parallel walker drops in here as cdp.go.
package lldp

// LLDP-MIB OIDs (IEEE 802.1AB, dot1abLldpMIB = 1.0.8802.1.1.2)
//
// The remote table (lldpRemTable) is indexed by:
//   (lldpRemTimeMark, lldpRemLocalPortNum, lldpRemIndex)
//
// So a BulkWalk on lldpRemSysName returns OIDs like:
//   1.0.8802.1.1.2.1.4.1.1.9.<TimeMark>.<LocalPort>.<Index>
//
// We only care about the (LocalPort, Index) tail to correlate the columns
// of one neighbor entry; TimeMark is opaque to us.
const (
	// Local port descriptive name (so we can map LocalPortNum → "GigabitEthernet0/1")
	OIDLldpLocPortDesc = "1.0.8802.1.1.2.1.3.7.1.4"

	// Remote neighbor columns
	OIDLldpRemChassisIdSubtype = "1.0.8802.1.1.2.1.4.1.1.4"
	OIDLldpRemChassisId        = "1.0.8802.1.1.2.1.4.1.1.5"
	OIDLldpRemPortIdSubtype    = "1.0.8802.1.1.2.1.4.1.1.6"
	OIDLldpRemPortId           = "1.0.8802.1.1.2.1.4.1.1.7"
	OIDLldpRemPortDesc         = "1.0.8802.1.1.2.1.4.1.1.8"
	OIDLldpRemSysName          = "1.0.8802.1.1.2.1.4.1.1.9"
	OIDLldpRemSysDesc          = "1.0.8802.1.1.2.1.4.1.1.10"

	// IF-MIB columns we use to derive interface speed
	OIDIfDescr = "1.3.6.1.2.1.2.2.1.2"
	OIDIfSpeed = "1.3.6.1.2.1.2.2.1.5"  // bits/sec
)

// LLDP chassisId / portId subtype enums per LLDP-MIB.
// Documented inline so callers don't have to grep the RFC.
const (
	ChassisIdSubtypeMACAddress     = 4
	ChassisIdSubtypeNetworkAddress = 5
	ChassisIdSubtypeIfName         = 6
	ChassisIdSubtypeLocal          = 7

	PortIdSubtypeIfAlias       = 1
	PortIdSubtypePortComponent = 2
	PortIdSubtypeMACAddress    = 3
	PortIdSubtypeNetworkAddress = 4
	PortIdSubtypeIfName        = 5
	PortIdSubtypeAgentCircuitID = 6
	PortIdSubtypeLocal         = 7
)
