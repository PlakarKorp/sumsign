package main

import (
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s <command> [options]\n", os.Args[0])
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	usage()
	os.Exit(1)
}
