package transport

import (
	"context"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// ReportTopology forwards a discovery batch (LLDP/CDP) to the central server.
// Wraps the bare gRPC stub so callers don't need access to Conn internals;
// errors are returned verbatim so the runner can log/skip a bad cycle without
// killing the process.
func (c *Conn) ReportTopology(ctx context.Context, report *collectorv1.TopologyReport) (*collectorv1.TopologyAck, error) {
	return c.client.ReportTopology(ctx, report)
}
