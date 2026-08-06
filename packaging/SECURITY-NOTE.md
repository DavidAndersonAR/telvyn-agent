# Packaging security note

Third-party attribution for `install.sh` is consolidated in
`../THIRD_PARTY_NOTICES.md`.

## Threat note (T-03-08-01 / T-03-08-06)

`install.sh` itself is not GPG-signed in this phase — integrity rests
on HTTPS transport (`curl --proto '=https'`) plus SHA256 verification
of the downloaded tarball. A modify-both attack against tarball + sidecar
served from the same origin is accepted residual risk until GPG signing
ships with `.deb` / `.rpm` packaging (deferred phase).
