// spanwal.go provides an on-disk WAL for SpanBatch values, mirroring the
// metrics WAL (wal.go) so traces survive a backend restart or a multi-hour
// POP isolation with the same guarantees:
//
//   - Append(batch) persists the SpanBatch BEFORE the gRPC sender sees it.
//     Returns a monotonic sequence number used as both bbolt key and
//     SpanBatch.batch_seq on the wire.
//   - Ack(seq) removes the entry — called when the server returns a SpanAck
//     with no rejected count and no error.
//   - Iterate(fn) walks pending entries oldest-first for replay on startup
//     or after reconnect.
//   - DropOldestUntilSize enforces a soft byte cap by deleting OLDEST entries
//     first (never newest) until file size drops below target.
//
// Design choice: spans live in a SEPARATE bbolt file (own *bolt.DB) rather
// than a second bucket in the metrics WAL. Rationale:
//   - Independent byte budget: metrics are critical and must not have their
//     1GB cap eaten by a span flood; a separate file lets ops size each cap
//     independently (WalMaxBytes vs SpanWalMaxBytes).
//   - bbolt cap enforcement here is file-size based (os.Stat); sharing a file
//     would make per-stream cap accounting ambiguous.
//   - Failure isolation: a corrupt span WAL never blocks metric durability.
//
// Durability/concurrency match wal.WAL exactly (every Update fsyncs;
// single-writer / multi-reader via bbolt Tx serialization).
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

var bucketSpansPending = []byte("spans_pending")

// SpanWAL is an on-disk write-ahead log for SpanBatch values backed by bbolt.
type SpanWAL struct {
	db       *bolt.DB
	path     string
	maxBytes int64

	nextSeq atomic.Uint64

	closeMu sync.Mutex
	closed  bool
}

// OpenSpanWAL creates or reopens the span WAL at path. maxBytes is the soft
// cap; set 0 to disable cap enforcement (tests only). The sequence counter
// resumes from the last stored entry so replays assign the correct WAL seq
// to SpanBatch.batch_seq.
func OpenSpanWAL(path string, maxBytes int64) (*SpanWAL, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("span wal open %s: %w", path, err)
	}
	w := &SpanWAL{db: db, path: path, maxBytes: maxBytes}
	err = db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketSpansPending)
		if err != nil {
			return err
		}
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

// Append persists batch and returns its assigned sequence number. The
// sequence is monotonic per WAL file and survives restart.
func (w *SpanWAL) Append(batch *collectorv1.SpanBatch) (uint64, error) {
	w.closeMu.Lock()
	if w.closed {
		w.closeMu.Unlock()
		return 0, errors.New("span wal: closed")
	}
	w.closeMu.Unlock()

	data, err := proto.Marshal(batch)
	if err != nil {
		return 0, fmt.Errorf("span wal marshal: %w", err)
	}
	seq := w.nextSeq.Add(1) - 1
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)
	err = w.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSpansPending).Put(key, data)
	})
	if err != nil {
		return 0, fmt.Errorf("span wal put: %w", err)
	}
	// Cap enforcement: drop OLDEST when file grows beyond soft cap.
	if w.maxBytes > 0 {
		if size, serr := w.Size(); serr == nil && size > w.maxBytes {
			_ = w.dropOldestUntilSize(int64(float64(w.maxBytes) * 0.8))
		}
	}
	return seq, nil
}

// Ack removes the entry at seq. Idempotent (Delete of missing key is no-op).
func (w *SpanWAL) Ack(seq uint64) error {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)
	return w.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSpansPending).Delete(key)
	})
}

// PendingSpan holds a span WAL entry returned by Iterate.
type PendingSpan struct {
	Seq   uint64
	Batch *collectorv1.SpanBatch
}

// Iterate calls fn for every pending entry in seq order (oldest first).
func (w *SpanWAL) Iterate(fn func(PendingSpan) error) error {
	return w.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketSpansPending).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			batch := &collectorv1.SpanBatch{}
			if err := proto.Unmarshal(v, batch); err != nil {
				// Poison pill — skip and continue.
				continue
			}
			if err := fn(PendingSpan{Seq: binary.BigEndian.Uint64(k), Batch: batch}); err != nil {
				return err
			}
		}
		return nil
	})
}

// Size returns the WAL file size in bytes.
func (w *SpanWAL) Size() (int64, error) {
	info, err := os.Stat(w.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// dropOldestUntilSize deletes the oldest (lowest-seq) entries in chunks of 10
// until the file size drops below target. Called by Append on cap overflow.
func (w *SpanWAL) dropOldestUntilSize(target int64) error {
	dropped := 0
	err := w.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSpansPending)
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
		fmt.Fprintf(os.Stderr, "span wal: dropped %d oldest entries (cap enforcement)\n", dropped)
	}
	return err
}

// DropOldestUntilSize is the exported version used by tests and external
// callers that want to trigger cap enforcement explicitly.
func (w *SpanWAL) DropOldestUntilSize(target int64) error {
	return w.dropOldestUntilSize(target)
}

// Close flushes and closes the underlying bolt DB. Idempotent.
func (w *SpanWAL) Close() error {
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	return w.db.Close()
}
