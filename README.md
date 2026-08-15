# sumsign

Sign SHA256 checksum files for plakar package distribution.

Given a secret key and a path, `sumsign` walks the path and signs every `.sum`
file that is not already covered by a valid signature, emitting `<name>.sum.sig`
next to it.

```
$ sumsign -s plakar-20260815.sec artifacts/
passphrase:
artifacts/s3/recipe.yaml.sum: signed
artifacts/s3/s3_v1.1.2_linux_amd64.ptar.sum: signed
2 signed, 0 re-signed, 0 up to date, 0 failed
```

## Formats

Checksum files are in BSD tagged form, as emitted by OpenBSD `sha256(1)` and by
`krossbuild`:

```
SHA256 (s3_v1.1.2_linux_amd64.ptar) = e285ed22e6...
```

To generate one by hand:

```sh
sha256(1)                                   # OpenBSD
sha256sum --tag <file> > <file>.sum         # Linux, coreutils >= 8.26
```

GNU `sha256sum --tag` output is byte-identical to what `krossbuild` writes. Both
`sha256sum -c` and `shasum -a 256 -c` auto-detect tagged input, so verifying a
`.sum` needs no special flag on either platform. Run them from the directory
containing the file: tagged form records whatever path it was given, and
`krossbuild` always records the bare basename.

Signatures are [signify](https://man.openbsd.org/signify) format — ed25519,
detached, wire-compatible with `signify(1)`, so artifacts can be verified
without this tool:

```
$ signify -V -p plakar-20260815.pub -m foo.ptar.sum -x foo.ptar.sum.sig
Signature Verified
```

## Existing signatures are verified, not trusted

A `.sum` that already has a `.sum.sig` is not skipped on the strength of the
signature file existing. The signature is checked against the `.sum` first:

- valid → skipped
- present but stale → re-signed
- absent → signed

A `.sum` regenerated after its signature was written (rebuilt artifact, edited
recipe) would otherwise keep a signature that no longer matches, in a tree that
looks fully signed. Repeated runs are therefore self-healing. `-f` re-signs
everything regardless.

## Key naming drives the signature comment

signify names the public key after the secret key, so the secret key's filename
determines what the signature tells verifiers to check against:

```
plakar-20260815.sec  →  untrusted comment: verify with plakar-20260815.pub
```

Dating the key file is what makes rotation legible: a signature names the exact
public key that verifies it, so several keys can be in circulation at once.

## Passphrase

Prompted on the terminal with echo off, or read from stdin when it is not a
terminal. `-passphrase-file` reads it from a file for unattended runs. Keys
generated with `signify -G -n` (`kdfrounds` = 0) are unencrypted and are not
prompted for.

Nothing sensitive is accepted on the command line, where it would be visible in
`ps` and in shell history.

## Usage

```
usage: sumsign -s seckey [-passphrase-file file] [-f] [-q] path...
  -f    re-sign even when the existing signature is valid
  -passphrase-file string
        read passphrase from file instead of prompting
  -q    only report files that were signed
  -s string
        secret key file
```

Exits nonzero if any file failed to sign.
