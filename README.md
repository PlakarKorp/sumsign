# sumsign

Sign and verify SHA256 checksum files for plakar package distribution.

Checksum files are in BSD tagged form, as emitted by OpenBSD `sha256(1)` and by
`krossbuild`:

```
SHA256 (s3_v1.1.2_linux_amd64.ptar) = e285ed22e6...
```

Signatures are [signify](https://man.openbsd.org/signify) format — ed25519,
detached, wire-compatible with `signify(1)` so artifacts can be verified without
this tool.

## Status

Skeleton. Nothing implemented yet.
