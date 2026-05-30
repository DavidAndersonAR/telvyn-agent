// Package adapters defines the contract every collection source must
// satisfy. Adapters run in their own goroutines, push batches of metrics
// onto a shared output channel, and the transport layer (t1-5) takes it
// from there.
package adapters

import (
	"context"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

type Adapter interface {
	// Name uniquely identifies the adapter for logging/metrics.
	Name() string

	// Run blocks until ctx is cancelled or a fatal error happens.
	// On normal cancellation returns nil; on fatal error returns the error.
	// Adapters MUST drain on ctx.Done() and not leak goroutines.
	Run(ctx context.Context, out chan<- []*collectorv1.Metric) error
}
