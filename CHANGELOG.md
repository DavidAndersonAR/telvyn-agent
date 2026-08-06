# Changelog

All notable changes to the IspWatch Agent are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Update `## [Unreleased]` as commits land. On release, move entries to a
> versioned section (`## [0.X.0] - YYYY-MM-DD`) and bump the heading.

## [Unreleased]

### Added

- Continuous SNMP coverage via `snmp.generic` check with bundled vendor profiles
  (`linux-net-snmp`, `cisco-ios`, `cisco-nx-os`, `juniper-junos`,
  `mikrotik-routeros`, `generic-snmpv2`). SNMP v2c + v3 (USM auth/priv including
  Reeder/Blumenthal AES variants) supported via `internal/snmp/`.
- Continuous ICMP coverage via `icmp.ping` check (RTT min/max/avg/stddev,
  packet loss, jitter). Uses `prometheus-community/pro-bing` with raw socket
  (`CAP_NET_RAW` granted by the systemd unit).
- Cardinality budget enforcement via Tagger middleware (per-host scope).
  Default budget 10 000 series/host with 24 h sliding window. Excess series
  dropped, meta-metric `ispwatch.tagger.dropped{host,metric}` emitted.
- SNMP autodiscovery v0: scan operator-configured CIDRs, candidate hosts
  persisted as `Host` records pending operator approval.
- Linux distribution via GitHub Releases (tarball + SHA256 sidecar) and
  canonical `install.sh` script supporting Ubuntu 20.04+, Debian 11+,
  Rocky/RHEL 8+, AlmaLinux 9+. systemd unit hardened per
  `03-RESEARCH.md §Security Domain` (NoNewPrivileges, ProtectSystem=strict,
  AmbientCapabilities=CAP_NET_RAW, AF_NETLINK in RestrictAddressFamilies,
  SystemCallFilter=@system-service ~ @privileged @raw-io ...).
- `--version` flag on `ispwatch-agent` binary. Version string injected at
  build time via `-ldflags="-X main.Version=${GITHUB_REF_NAME}"`.
- Reproducible release pipeline: `make release-ci` (CI) and `make release-local`
  (ops) produce identical tarballs `ispwatch-agent-<version>-linux-<arch>.tar.gz`
  with binary + `ispwatch-agent.service` + `LICENSE` +
  `THIRD_PARTY_NOTICES.md`, plus `.sha256`
  sidecar.
- GitHub Actions workflow `.github/workflows/release.yml` — tag-triggered
  (`v*`) multi-arch build (`linux/amd64`, `linux/arm64`) publishing the tarball
  assets to a single GitHub Release (what `install.sh` downloads).
- Certless Linux install: `install.sh` + systemd unit authenticate via ingest
  Bearer token (`ISPWATCH_INGEST_URL` + `ISPWATCH_INGEST_TOKEN`), config through
  an `EnvironmentFile` (`/etc/ispwatch/agent.env`) — the mTLS enrollment path
  and `config-template.yaml` were retired.

### Changed

- Refactored `tools/snmp.go` to share its low-level client with the new
  `snmp.generic` check via the `internal/snmp/` package; SNMP v3 is now
  exposed in tool args.

### Deferred (out of scope this phase)

- Windows agent (`windows.system`) — scoped CHECK-03, deferred.
- Mikrotik RouterOS binary API (`mikrotik.routeros` dedicated check) —
  coverage provided via SNMP profile in this phase.
- `.deb` / `.rpm` packaging with GPG signing — tarball + SHA256 first; GPG
  pinning of the workflow's `softprops/action-gh-release@v2` to a specific SHA
  is also deferred (currently pinned to the major version `@v2`).
- Install telemetry, agent upgrade mode, multi-flavor variants
  (iot, FIPS, etc.).

## [0.3.0] - YYYY-MM-DD

(Initial Phase 3 release. Date and the final list of entries are filled in
when the `v0.3.0` tag is pushed and the release workflow publishes the
GitHub Release.)
