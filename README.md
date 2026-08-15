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
**embedded**, wire-compatible with `signify(1)`, so artifacts can be verified
without this tool:

```
$ signify -V -e -p plakar-20260815.pub -x foo.ptar.sum.sig -m /dev/stdout
Signature Verified
SHA256 (foo.ptar) = e285ed22e6...
```

An embedded signature carries the checksum line inside the `.sig`, after the
signature:

```
untrusted comment: verify with plakar-20260815.pub
RWSoM/ECJgcd3O1Vf9FcLYCI+lPd5kSRKg4b2DV8nVrM9xNMBsMYa1ubwd…
SHA256 (foo.ptar) = e285ed22e60232c37c2604d13c46e48af3c5e40044542fe5fe3b86b9f7e62c7f
```

The standalone `.sum` is written and shipped as well, so three files travel per
artifact: `foo.ptar`, `foo.ptar.sum`, `foo.ptar.sum.sig`. The embedded copy is
the one that is signed; the standalone `.sum` is a convenience so stock
`sha256sum -c` can check the artifact with no signify involved. If the two ever
disagree, the embedded copy is authoritative — and `sumsign` re-signs to bring
them back into line.

## Existing signatures are verified, not trusted

A `.sum` that already has a `.sum.sig` is not skipped on the strength of the
signature file existing. Both the signature and the embedded copy are checked
against the standalone `.sum` first:

- signature valid **and** embedded copy matches the `.sum` → skipped
- signature stale, or embedded copy disagrees with the `.sum` → re-signed
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

Only the basename is used. `signify(1)` embeds whatever path it was invoked
with, so signing with `-s /var/lib/build/.signify/plakar-20260815.sec` would
otherwise publish the layout of the signing host in every signature.

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
