# Third-party license notices

## install.sh

`install.sh` is inspired by Datadog's `install_script.sh.template`
(https://github.com/DataDog/agent-linux-install-script), licensed under
the Apache License, Version 2.0.

We adopted the following patterns from the Datadog script:

- Cascading distro detection (`lsb_release` → `/etc/os-release` → `uname`)
- `curl --retry 5 --retry-delay 5` retry pattern
- `trap on_error ERR` + `trap on_exit EXIT` for error handling and cleanup
- Substitution of config placeholders via `sed` after copying a template

We do NOT include the following elements of the Datadog script:

- Installation telemetry (POST to a backend with install statistics)
- Multi-flavor variants (`agent` / `iot-agent` / `fips-agent`)
- Agent 5 → 7 upgrade mode (no legacy install to preserve)
- Multiple GPG keys handling
- Parallel download

The Apache-2.0 license terms apply to the adapted portions. A copy of
the license is available at https://www.apache.org/licenses/LICENSE-2.0.

## Threat note (T-03-08-01 / T-03-08-06)

`install.sh` itself is not GPG-signed in this phase — integrity rests
on HTTPS transport (`curl --proto '=https'`) plus SHA256 verification
of the downloaded tarball. A modify-both attack against tarball + sidecar
served from the same origin is accepted residual risk until GPG signing
ships with `.deb` / `.rpm` packaging (deferred phase).
