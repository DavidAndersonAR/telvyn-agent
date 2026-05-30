# internal/ebpf

eBPF-based L7 protocol tracing for the ISPWatch agent.

## Origin

All code in this directory tree (including the `common/`, `proc/`, `cgroup/`,
`flags/`, `l7/`, and `ebpf/` subdirectories) is **derived from
[coroot-node-agent](https://github.com/coroot/coroot-node-agent)**, Copyright
(C) Coroot Labs, licensed under the **Apache License, Version 2.0**.

See `../NOTICE` and `../LICENSE-APACHE-2.0` for the full attribution and
license text.

## Mapping to upstream

| Upstream path | Local path |
|---|---|
| `ebpftracer/` (excluding `ebpf/` subdir) | `./` (package renamed `ebpftracer` → `ebpf`) |
| `ebpftracer/ebpf/` | `./ebpf/` (C sources, unchanged build) |
| `ebpftracer/l7/` | `./l7/` |
| `common/` | `./common/` |
| `proc/` | `./proc/` |
| `cgroup/` | `./cgroup/` |
| `flags/` | `./flags/` |

## ISPWatch modifications

- Go package `ebpftracer` renamed to `ebpf` to match our `internal/ebpf/`
  layout.
- All `github.com/coroot/coroot-node-agent/...` imports rewritten to
  `github.com/ispwatch/collector/internal/ebpf/...`.
- Output integration: events from the tracer are forwarded to the agent's
  gRPC `StreamSpans` transport instead of the upstream Prometheus pusher.
- (Future) container/pod discovery may be replaced by our own `k8s.kubelet`
  discovery (`internal/checks/k8s/...`).

## What it does

The tracer:

1. Loads eBPF programs (compiled from `ebpf/`) into the kernel as kprobes on
   `tcp_sendmsg` / `tcp_recvmsg` and as uprobes on libssl / Go TLS / Rustls.
2. Reads protocol-decoded events from a ringbuf in userspace.
3. Maps each event to a Kubernetes pod via cgroup → container_id → pod.
4. Emits an OTLP span per request (HTTP, Postgres query, Redis command, …)
   and updates local Prometheus histograms for p50/p95/throughput.

Covered L7 protocols (decoders in `ebpf/l7/*.c` + Go parsers in `l7/*.go`):

HTTP/1.1, HTTP/2, Postgres, Redis, Memcached, MySQL, MongoDB, Cassandra,
Kafka, NATS, RabbitMQ, Dubbo2, DNS, ClickHouse, ZooKeeper, FoundationDB.

TLS plaintext extraction via uprobes:

OpenSSL (`libssl`), Go (`crypto/tls`), Rustls, Java TLS, Node.js (BoringSSL).
