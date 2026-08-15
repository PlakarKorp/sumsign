package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

const sumSuffix = ".sum"

type action int

const (
	actionSign action = iota
	actionResign
	actionSkip
)

func (a action) String() string {
	switch a {
	case actionSign:
		return "signed"
	case actionResign:
		return "re-signed (stale signature)"
	default:
		return "skipped"
	}
}

func sigPath(path string) string {
	return path + ".sig"
}

// findSums walks root and returns every .sum file below it, sorted by
// filepath.WalkDir's lexical order so runs are reproducible.
func findSums(root string) ([]string, error) {
	var sums []string

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(d.Name(), sumSuffix) {
			return nil
		}

		sums = append(sums, path)

		return nil
	})

	return sums, err
}

// readPassphrase prompts on the terminal with echo off, or reads a single line
// from stdin when it is not a terminal, matching signify(1).
func readPassphrase() ([]byte, error) {
	fmt.Fprintf(os.Stderr, "passphrase: ")

	if term.IsTerminal(int(os.Stdin.Fd())) {
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr, "")

		return pass, err
	}

	line, err := bufio.NewReader(os.Stdin).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}

	return bytes.TrimRight(line, "\r\n"), nil
}

// passphraseFromFile reads a passphrase from a file, taking the first line so
// a trailing newline does not become part of the secret.
func passphraseFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		data = data[:i]
	}

	return bytes.TrimRight(data, "\r"), nil
}

// signSum signs one .sum file, deciding whether it needs signing at all. An
// existing signature is verified rather than trusted: a .sum regenerated after
// its signature was written would otherwise keep a signature that no longer
// matches it, in a tree that looks fully signed.
func signSum(
	path string,
	seckey ed25519.PrivateKey,
	keynum [keynumlen]byte,
	comment string,
	force bool,
) (action, error) {
	msg, err := os.ReadFile(path)
	if err != nil {
		return actionSkip, err
	}

	act := actionSign

	if _, err := os.Stat(sigPath(path)); err == nil {
		act = actionResign

		if !force {
			existing, err := readSig(sigPath(path))
			if err == nil && verifyMessage(seckey, keynum, msg, existing) {
				return actionSkip, nil
			}
		}
	}

	if err := writeb64file(
		sigPath(path),
		comment,
		signMessage(seckey, keynum, msg),
	); err != nil {
		return actionSkip, err
	}

	return act, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s -s seckey [-passphrase-file file] [-f] [-q] path...\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var seckeyfile string
	var passfile string
	var force bool
	var quiet bool

	flag.StringVar(&seckeyfile, "s", "", "secret key file")
	flag.StringVar(&passfile, "passphrase-file", "", "read passphrase from file instead of prompting")
	flag.BoolVar(&force, "f", false, "re-sign even when the existing signature is valid")
	flag.BoolVar(&quiet, "q", false, "only report files that were signed")

	flag.Usage = usage
	flag.Parse()

	if seckeyfile == "" || flag.NArg() == 0 {
		usage()
		os.Exit(1)
	}

	// Collect the work before asking for the passphrase, so a mistyped path
	// fails before the user types a secret.
	var sums []string

	for _, root := range flag.Args() {
		found, err := findSums(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", root, err)
			os.Exit(1)
		}

		sums = append(sums, found...)
	}

	if len(sums) == 0 {
		fmt.Fprintf(os.Stderr, "no %s files found\n", sumSuffix)
		os.Exit(1)
	}

	encrypted, err := isEncrypted(seckeyfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var passphrase []byte

	if encrypted {
		if passfile != "" {
			passphrase, err = passphraseFromFile(passfile)
		} else {
			passphrase, err = readPassphrase()
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to read passphrase: %v\n", err)
			os.Exit(1)
		}

		if len(passphrase) == 0 {
			fmt.Fprintln(os.Stderr, "please provide a passphrase")
			os.Exit(1)
		}
	}

	seckey, keynum, comment, err := loadSeckey(seckeyfile, passphrase)
	zero(passphrase)

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	defer zero(seckey)

	var signed, resigned, skipped, failed int

	for _, path := range sums {
		act, err := signSum(path, seckey, keynum, comment, force)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			failed++
			continue
		}

		switch act {
		case actionSign:
			signed++
		case actionResign:
			resigned++
		default:
			skipped++
		}

		if !quiet || act != actionSkip {
			fmt.Printf("%s: %s\n", path, act)
		}
	}

	fmt.Fprintf(
		os.Stderr,
		"%d signed, %d re-signed, %d up to date, %d failed\n",
		signed,
		resigned,
		skipped,
		failed,
	)

	if failed > 0 {
		os.Exit(1)
	}
}
