//go:build linux || darwin

// Command nocklock-install activates verified Linux release pairs.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/nocktechnologies/nocklock/internal/linuxinstall"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "install" && os.Args[1] != "rollback") {
		fmt.Fprintln(os.Stderr, "Usage: nocklock-install install --tag vX.Y.Z --artifacts DIR --cosign FILE [--egress-user USER]\n       nocklock-install rollback --tag vX.Y.Z --cosign FILE")
		os.Exit(2)
	}
	var o linuxinstall.Options
	o.Rollback = os.Args[1] == "rollback"
	flags := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	flags.StringVar(&o.Tag, "tag", "", "explicit stable release tag")
	flags.StringVar(&o.Artifacts, "artifacts", "", "directory containing archive, SHA256SUMS and Sigstore bundle")
	flags.StringVar(&o.Cosign, "cosign", "", "Cosign v3.1.3 Linux amd64 binary (checksum pinned)")
	flags.StringVar(&o.EgressUser, "egress-user", "", "explicitly grant constrained netns helper access to this local account")
	flags.Parse(os.Args[2:])
	if flags.NArg() != 0 || o.Tag == "" || o.Cosign == "" || (!o.Rollback && o.Artifacts == "") || (o.Rollback && o.Artifacts != "") {
		flags.Usage()
		os.Exit(2)
	}
	if err := linuxinstall.Run(o); err != nil {
		fmt.Fprintln(os.Stderr, "nocklock-install:", err)
		os.Exit(1)
	}
	fmt.Printf("Activated %s. Run nocklock doctor in your project as your normal account; installation alone does not prove enforcement.\n", o.Tag)
}
