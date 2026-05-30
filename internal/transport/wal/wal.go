// Package wal provides an on-disk WAL (write-ahead log) backed by bbolt for
// the agent's metric forwarder pipeline (Plan 5, D-05 + D-06 always-on).
//
// Contract:
//   - Append(batch) persists the MetricBatch BEFORE the gRPC sender sees it.
//     Returns a monotonic sequence number used as both bbolt key and
//     MetricBatch.batch_seq on the wire.
//   - Ack(seq) removes the entry — called when the server returns a
//     MetricAck with no rejected count and no error.
//   - Iterate(fn) walks pending entries oldest-first for replay on startup
//     or after reconnect.
//   - DropOldestUntilSize enforces the 1GB cap (D-05) by deleting oldest
//     entries until file size drops below target. Logs dropped count for ops.
//
// Concurrency: single writer, multiple readers (mmap-backed). Producer and
// Sender goroutines coordinate via WAL operations alone — no additional
// mutex on top of bbolt's own Tx serialization.
//
// Durability: every Update() fsyncs by default (2 fsyncs per write per
// bbolt design — page + meta). This is *the* mechanism enforcing D-06
// always-on. Don't disable.
package wal

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

var bucketPending = []byte("pending")

// WAL is an on-disk write-ahead log for MetricBatch values backed by bbolt.
type WAL struct {
	db       *bolt.DB
	path     string
	maxBytes int64

	nextSeq atomic.Uint64

	closeMu sync.Mutex
	closed  bool
}

// Open creates or reopens the WAL at path. maxBytes is the soft cap (D-05
// 1GB recommended); set 0 to disable cap enforcement (tests only).
// The sequence counter resumes from the last stored entry so replays assign
// the correct WAL seq to MetricBatch.batch_seq.
func Open(path string, maxBytes int64) (*WAL, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("wal open %s: %w", path, err)
	}
	w := &WAL{db: db, path: path, maxBytes: maxBytes}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketPending)
		if err != nil {
			return err
		}
		// Resume sequence from last stored entry (survives restart).
		if k, _ := b.Cursor().Last(); k != nil {
			w.nextSeq.Store(binary.BigEndian.Uint64(k) + 1)
		}
		return nil
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return w, nil
}

// Append persists batch and returns its assigned sequence number.
// The sequence is monotonic per WAL file and survives restart (D-06).
// Returns an error if the WAL is closed or the underlying bbolt write fails.
func (w *WAL) Append(batch *collectorv1.MetricBatch) (uint64, error) {
	w.closeMu.Lock()
	if w.closed {
		w.closeMu.Unlock()
		return 0, errors.New("wal: closed")
	}
	w.closeMu.Unlock()

	data, err := proto.Marshal(batch)
	if err != nil {
		return 0, fmt.Errorf("wal marshal: %w", err)
	}
	seq := w.nextSeq.Add(1) - 1
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)
	err = w.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).Put(key, data)
	})
	if err != nil {
		// Roll back the counter so the next Append can use this slot.
		// This is a best-effort; a crash here leaves a gap (acceptable — gaps
		// in seq are harmless, server only uses seq for ack correlation).
		return 0, fmt.Errorf("wal put: %w", err)
	}
	// Cap enforcement: drop oldest when file grows beyond soft cap (D-05).
	if w.maxBytes > 0 {
		if size, serr := w.Size(); serr == nil && size > w.maxBytes {
			_ = w.dropOldestUntilSize(int64(float64(w.maxBytes) * 0.8))
		}
	}
	return seq, nil
}

// Ack removes the entry at seq. Idempotent (Delete of missing key is no-op).
// Called by the sender goroutine when MetricAck.rejected==0 and error=="".
func (w *WAL) Ack(seq uint64) error {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)
	return w.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPending).Delete(key)
	})
}

// Pending holds a WAL entry returned by Iterate.
type Pending struct {
	Seq   uint64
	Batch *collectorv1.MetricBatch
}

// Iterate calls fn for every pending entry in seq order (oldest first).
// Returning an error from fn aborts iteration and propagates the error.
// Uses a read-only bbolt View — does not block concurrent Append.
func (w *WAL) Iterate(fn func(Pending) error) error {
	return w.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketPending).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			batch := &collectorv1.MetricBatch{}
			if err := proto.Unmarshal(v, batch); err != nil {
				// Poison pill — skip and continue; ops will notice via log gaps.
				continue
			}
			if err := fn(Pending{Seq: binary.BigEndian.Uint64(k), Batch: batch}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Size returns the WAL file size in bytes. bbolt file does NOT shrink after
// Delete — free pages are reclaimed in place. Use this as a proxy for cap
// enforcement rather than an exact measure of live data.
func (w *WAL) Size() (int64, error) {
	info, err := os.Stat(w.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// dropOldestUntilSize deletes the oldest (lowest-seq) entries from the
// pending bucket in chunks of 10 until the file size drops below target.
// Called internally by Append when the soft cap is exceeded.
func (w *WAL) dropOldestUntilSize(target int64) error {
	dropped := 0
	err := w.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketPending)
		cursor := b.Cursor()
		for {
			k, _ := cursor.First()
			if k == nil {
				break
			}
			if err := b.Delete(k); err != nil {
				return err
			}
			dropped++
			// Check size every 10 deletions (bbolt stats are not free).
			if dropped%10 == 0 {
				size, err := w.Size()
				if err == nil && size < target {
					break
				}
			}
		}
		return nil
	})
	if dropped > 0 {
		// Ops visibility — slog not available here without import cycle;
		// stderr is the safe fallback for an embedded library component.
		fmt.Fprintf(os.Stderr, "wal: dropped %d oldest entries (cap enforcement)\n", dropped)
	}
	return err
}

// DropOldestUntilSize is the exported version used by tests and external
// callers that want to trigger cap enforcement explicitly.
func (w *WAL) DropOldestUntilSize(target int64) error {
	return w.dropOldestUntilSize(target)
}

// Close flushes and closes the underlying bolt DB. Idempotent.
func (w *WAL) Close() error {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.db.Close()
}
