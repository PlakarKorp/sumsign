package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ebfe/bcrypt_pbkdf"
)

// Wire format of OpenBSD signify(1). Layouts are fixed-size and read with
// binary.Read, so they must not be reordered or padded.
const (
	pkalg      = "Ed"
	kdfalg     = "BK"
	keynumlen  = 8
	commenthdr = "untrusted comment: "
	verifywith = "verify with "

	commentmaxlen = 1024
)

type enckey struct {
	Pkalg     [2]byte
	Kdfalg    [2]byte
	Kdfrounds [4]byte
	Salt      [16]byte
	Checksum  [8]byte
	Keynum    [keynumlen]byte
	Seckey    [ed25519.PrivateKeySize]byte
}

type pubkey struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Pubkey [ed25519.PublicKeySize]byte
}

type sig struct {
	Pkalg  [2]byte
	Keynum [keynumlen]byte
	Sig    [ed25519.SignatureSize]byte
}

// readb64file parses a signify file: a "untrusted comment: ..." line followed
// by one line of base64. It returns the comment and the decoded payload.
func readb64file(path string) (string, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}

	lines := strings.SplitN(string(data), "\n", 3)
	if len(lines) < 2 {
		return "", nil, fmt.Errorf("%s: invalid format", path)
	}

	if !strings.HasPrefix(lines[0], commenthdr) {
		return "", nil, fmt.Errorf("%s: missing comment header", path)
	}

	comment := strings.TrimPrefix(lines[0], commenthdr)

	buf, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil {
		return "", nil, fmt.Errorf("%s: invalid base64: %w", path, err)
	}

	if len(buf) < 2 || string(buf[:2]) != pkalg {
		return "", nil, fmt.Errorf("%s: unsupported algorithm", path)
	}

	return comment, buf, nil
}

// writeb64file writes a signify file with the given comment and payload.
func writeb64file(path, comment string, data any) error {
	if len(commenthdr)+len(comment) >= commentmaxlen {
		return errors.New("comment too long")
	}

	var buf bytes.Buffer

	if err := binary.Write(&buf, binary.BigEndian, data); err != nil {
		return err
	}

	content := fmt.Sprintf(
		"%s%s\n%s\n",
		commenthdr,
		comment,
		base64.StdEncoding.EncodeToString(buf.Bytes()),
	)

	return os.WriteFile(path, []byte(content), 0644)
}

// decryptSeckey decrypts a secret key with the given passphrase. A key with
// kdfrounds == 0 is unencrypted and the passphrase is ignored, which is how
// signify supports unattended signing.
func decryptSeckey(enc *enckey, passphrase []byte) (ed25519.PrivateKey, error) {
	if string(enc.Kdfalg[:]) != kdfalg {
		return nil, errors.New("unsupported KDF")
	}

	rounds := int(binary.BigEndian.Uint32(enc.Kdfrounds[:]))

	xorkey := make([]byte, len(enc.Seckey))

	if rounds > 0 {
		if len(passphrase) == 0 {
			return nil, errors.New("passphrase required")
		}

		copy(xorkey, bcrypt_pbkdf.Key(
			passphrase,
			enc.Salt[:],
			rounds,
			len(xorkey),
		))
	}

	seckey := make([]byte, len(enc.Seckey))

	for i := range enc.Seckey {
		seckey[i] = enc.Seckey[i] ^ xorkey[i]
	}

	zero(xorkey)

	// The checksum is what tells a wrong passphrase apart from a corrupt
	// key; without it we would emit signatures that verify against nothing.
	digest := sha512.Sum512(seckey)

	if !bytes.Equal(enc.Checksum[:], digest[:8]) {
		zero(seckey)
		return nil, errors.New("incorrect passphrase")
	}

	return ed25519.PrivateKey(seckey), nil
}

// loadSeckey reads and decrypts a secret key file, and derives the comment to
// put in signatures it produces. signify names the public key after the secret
// key, so "plakar.sec" yields "verify with plakar.pub".
func loadSeckey(path string, passphrase []byte) (ed25519.PrivateKey, [keynumlen]byte, string, error) {
	var enc enckey

	comment, buf, err := readb64file(path)
	if err != nil {
		return nil, enc.Keynum, "", err
	}

	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &enc); err != nil {
		return nil, enc.Keynum, "", fmt.Errorf("%s: %w", path, err)
	}

	seckey, err := decryptSeckey(&enc, passphrase)
	if err != nil {
		return nil, enc.Keynum, "", fmt.Errorf("%s: %w", path, err)
	}

	sigcomment := fmt.Sprintf("signature from %s", comment)

	if strings.HasSuffix(path, ".sec") {
		sigcomment = verifywith + strings.TrimSuffix(path, ".sec") + ".pub"
	}

	return seckey, enc.Keynum, sigcomment, nil
}

// isEncrypted reports whether a secret key file needs a passphrase.
func isEncrypted(path string) (bool, error) {
	var enc enckey

	_, buf, err := readb64file(path)
	if err != nil {
		return false, err
	}

	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &enc); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	return binary.BigEndian.Uint32(enc.Kdfrounds[:]) > 0, nil
}

// signMessage produces a detached signature over msg.
func signMessage(seckey ed25519.PrivateKey, keynum [keynumlen]byte, msg []byte) *sig {
	var s sig

	copy(s.Pkalg[:], pkalg)
	s.Keynum = keynum
	copy(s.Sig[:], ed25519.Sign(seckey, msg))

	return &s
}

// readSig loads a detached signature file.
func readSig(path string) (*sig, error) {
	var s sig

	_, buf, err := readb64file(path)
	if err != nil {
		return nil, err
	}

	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}

	return &s, nil
}

// verifyMessage checks a detached signature against msg using the public key
// derived from seckey, so a run can tell a stale signature from a current one
// without needing the public key file.
func verifyMessage(seckey ed25519.PrivateKey, keynum [keynumlen]byte, msg []byte, s *sig) bool {
	if !bytes.Equal(s.Keynum[:], keynum[:]) {
		return false
	}

	public, ok := seckey.Public().(ed25519.PublicKey)
	if !ok {
		return false
	}

	return ed25519.Verify(public, msg, s.Sig[:])
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
