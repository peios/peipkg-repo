// Command peipkg-repo turns a directory of .peipkg files into a
// publishable repository state (descriptor + indexes + signatures).
//
// Three subcommands:
//
//	init     create an empty repository state from scratch
//	publish  add packages incrementally to an existing state
//	verify   audit an existing state for integrity
//
// peipkg-repo emits a directory tree conforming to PSD-009 §6.4. It does
// not upload, serve, or otherwise publish the bytes — the operator's
// build farm runs `aws s3 sync`, `git push`, `gh release create`, or
// equivalent to put the tree in front of consumers.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/peios/peipkg-repo/internal/operate"
	"github.com/peios/peipkg-repo/internal/signature"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	sub, args := os.Args[1], os.Args[2:]

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_ = ctx // currently unused; kept for future cancellable operations

	var err error
	switch sub {
	case "init":
		err = cmdInit(args)
	case "publish":
		err = cmdPublish(args)
	case "verify":
		err = cmdVerify(args)
	case "-h", "--help", "help":
		usage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "peipkg-repo: unknown subcommand %q\n\n", sub)
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "peipkg-repo:", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "usage: peipkg-repo <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "subcommands:")
	fmt.Fprintln(w, "  init     create an empty repository state")
	fmt.Fprintln(w, "  publish  add packages to an existing repository state")
	fmt.Fprintln(w, "  verify   audit a repository state's integrity")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-repo init --name N --sign-key PATH --timestamp T --out DIR [--description D]")
		fs.PrintDefaults()
	}
	name := fs.String("name", "", "repository name (required, kebab-case recommended)")
	desc := fs.String("description", "", "human-readable one-line description (optional)")
	keyPath := fs.String("sign-key", "", "Ed25519 private key (PEM PKCS#8 or 32-byte raw seed) (required)")
	timestamp := fs.String("timestamp", "", "RFC 3339 UTC timestamp ending with 'Z' (required)")
	out := fs.String("out", "", "output directory (required, must be empty or non-existent)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	for n, v := range map[string]string{
		"--name":      *name,
		"--sign-key":  *keyPath,
		"--timestamp": *timestamp,
		"--out":       *out,
	} {
		if v == "" {
			fs.Usage()
			return fmt.Errorf("%s is required", n)
		}
	}

	priv, err := signature.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	if err := operate.Init(operate.InitConfig{
		Name:        *name,
		Description: *desc,
		SignKey:     priv,
		Timestamp:   *timestamp,
		Out:         *out,
	}); err != nil {
		return err
	}
	fmt.Printf("initialised repository %q at %s\n", *name, *out)
	return nil
}

func cmdPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-repo publish --in DIR --new DIR --sign-key PATH --timestamp T --out DIR [flags]")
		fs.PrintDefaults()
	}
	in := fs.String("in", "", "previous repository state directory (required)")
	newPkgs := fs.String("new", "", "directory containing new .peipkg files to add")
	keyPath := fs.String("sign-key", "", "Ed25519 private key (required)")
	timestamp := fs.String("timestamp", "", "RFC 3339 UTC timestamp ending with 'Z' (required)")
	out := fs.String("out", "", "output directory for the new state (required)")
	urlTemplate := fs.String("package-url-template", "", "URL template for new entries; placeholders {name}, {version}, {arch}, {filename}; default /p/{name}/{version}/{filename}")
	rebuild := fs.Bool("rebuild", false, "ignore previous archive; rehash every .peipkg from --all-packages-dir")
	allPkgs := fs.String("all-packages-dir", "", "directory containing every .peipkg ever published (required with --rebuild)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	for n, v := range map[string]string{
		"--in":        *in,
		"--sign-key":  *keyPath,
		"--timestamp": *timestamp,
		"--out":       *out,
	} {
		if v == "" {
			fs.Usage()
			return fmt.Errorf("%s is required", n)
		}
	}
	if !*rebuild && *newPkgs == "" {
		fs.Usage()
		return fmt.Errorf("--new is required (or use --rebuild + --all-packages-dir)")
	}

	priv, err := signature.LoadPrivateKey(*keyPath)
	if err != nil {
		return err
	}

	report, err := operate.Publish(operate.PublishConfig{
		In:                 *in,
		NewPackagesDir:     *newPkgs,
		SignKey:            priv,
		Timestamp:          *timestamp,
		Out:                *out,
		PackageURLTemplate: *urlTemplate,
		Rebuild:            *rebuild,
		AllPackagesDir:     *allPkgs,
	})
	if err != nil {
		return err
	}
	fmt.Printf("published index_version %d (%d new packages)\n", report.IndexVersion, len(report.Added))
	for _, f := range report.Added {
		fmt.Println("  +", f)
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: peipkg-repo verify --repo DIR [--mode metadata|hashes|both] [--all-packages-dir DIR]")
		fs.PrintDefaults()
	}
	repo := fs.String("repo", "", "repository state directory (required)")
	modeStr := fs.String("mode", "both", "one of metadata, hashes, both")
	allPkgs := fs.String("all-packages-dir", "", "directory containing .peipkg files (required when mode includes 'hashes')")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *repo == "" {
		fs.Usage()
		return fmt.Errorf("--repo is required")
	}

	var mode operate.VerifyMode
	switch *modeStr {
	case "metadata":
		mode = operate.VerifyMetadata
	case "hashes":
		mode = operate.VerifyHashes
	case "both":
		mode = operate.VerifyAll
	default:
		fs.Usage()
		return fmt.Errorf("--mode must be one of metadata, hashes, both (got %q)", *modeStr)
	}

	report, err := operate.Verify(operate.VerifyConfig{
		Repo:           *repo,
		Mode:           mode,
		AllPackagesDir: *allPkgs,
	})
	if err != nil {
		return err
	}

	for _, w := range report.Warnings {
		fmt.Fprintln(os.Stderr, "WARN:", w)
	}
	if report.OK {
		fmt.Println("OK")
		return nil
	}
	for _, e := range report.Issues {
		fmt.Fprintln(os.Stderr, "FAIL:", e)
	}
	return fmt.Errorf("%d issue(s) found", len(report.Issues))
}
