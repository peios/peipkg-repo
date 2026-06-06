// Package web holds the static package-browser site that peipkg-repo
// materialises into the repository state at publish time.
//
// The site is a client-side browser over the signed indexes
// (index/active.json, index/archive.json) and the per-package sidecars
// (manifest.json, files.json) that publish extracts from each .peipkg.
// It carries no secrets and is not signed: trust derives from the signed
// indexes it renders and the signed copies inside each package.
//
// Only index.html and the assets/ tree are embedded. The dev-only
// fixtures kept under web/index/ and web/p/ (both gitignored, populated
// from a live mirror for local preview) are deliberately NOT listed in
// the embed pattern, so they never ship inside the binary.
package web

import "embed"

//go:embed index.html assets
var FS embed.FS
