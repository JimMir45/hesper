# @jimmir45/hesper (npm wrapper)

`npx @jimmir45/hesper` downloads the platform binary from the Hesper GitHub
releases, caches it under `~/.cache/hesper/`, and runs it with argv
passthrough. The engine is a single static Go binary — this wrapper only
downloads, never builds.

- Pin a version: `HESPER_VERSION=v0.1.0 npx @jimmir45/hesper …`
- No release asset yet (pre-alpha): build from source — `go build -o hesper
  ./cmd/hesper` in the repo.

Not published to the npm registry yet; the scope decision
(`@jimmir45/hesper`) is recorded in docs/design.md §11 and revisit at M5.
