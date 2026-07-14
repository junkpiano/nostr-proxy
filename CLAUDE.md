# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An HTTP proxy API (`GET /api/ogp?url=...`) that fetches OGP/Twitter Card metadata from web pages, with heavy emphasis on SSRF protection and resource limits. It ships as two deployment targets sharing one core library:

1. **Native Axum server** (default) — `src/main.rs`, binary `nostr-proxy`
2. **Cloudflare Worker** — separate crate in `worker/`, compiled to WASM

## Commands

```bash
# Build & run native server
cargo build
RUST_LOG=info cargo run

# Unit tests (tests/unit_test.rs — pure functions, no server needed)
cargo test
cargo test test_truncate_utf8_safe_ascii   # single test

# Integration tests — require a running server on :3000.
# This script builds release, starts the server, runs tests, and cleans up:
./tests/run_integration_tests.sh

# Lint/format (CI enforces both; clippy warnings are errors)
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings

# Worker: compile check and local dev (needs `cargo install worker-build`, `npm i -g wrangler`)
cd worker && worker-build --release
cd worker && wrangler dev    # serves http://localhost:8787/api/ogp
```

CI (`.github/workflows/test.yml`) runs on PRs to main: fmt check, clippy, build, unit tests, integration tests, and `cargo audit`.

## Architecture

The dual-target split is driven by Cargo features in the root `Cargo.toml`:

- **`src/lib.rs` (root of shared logic)** — platform-independent code: URL validation (`validate_url`, `validate_worker_target_url`), private/reserved IP checks (`is_private_or_reserved_ip`), HTML meta-tag parsing with bloat limits (`parse_ogp`), the `OgpError` enum, and constants (`MAX_REDIRECTS`, `MAX_RESPONSE_SIZE`). Everything here must stay WASM-compatible.
- **`src/lib.rs::native` module** — gated behind the `native` feature (on by default). Contains the reqwest/hickory-resolver fetch path with DNS pre-resolution SSRF checks and streaming size limits. All native-only deps (axum, tokio, reqwest, hickory-resolver, tower-governor) are optional and pulled in by this feature.
- **`worker/` crate** — depends on `nostr-proxy` with `default-features = false`, so it gets only the shared logic. It reimplements the fetch loop using the `worker` crate's Fetch API. Workers cannot do DNS pre-resolution, so SSRF protection here relies on `validate_worker_target_url` instead: IP-literal blocking, hostname blocklists (localhost/.local/.internal/etc.), port restriction (80/443 only), and userinfo rejection. Rate limiting is also absent on the Worker (native uses tower-governor).

Both fetch paths implement the same invariants: manual redirect following with loop detection (max 3 hops, re-validating each hop), Content-Type restricted to HTML/XHTML, 1MB response cap, and identical error-to-status mapping (see `error_response` in `worker/src/lib.rs` and `ogp_handler` in `src/main.rs`). When changing limits, error messages, or validation behavior, update both targets and the README's API spec.

Security model details (blocked IP ranges, rate limits, resource limits) are documented in README.md — keep it in sync with code changes.
