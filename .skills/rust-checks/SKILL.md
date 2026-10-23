---
name: rust-checks
description: Run this repo's formatting and clippy gates and report the result. Use before committing or when asked to check the Rust code.
---

# rust-checks

Run from the repo root.

1. `cargo fmt --check`. If it fails, run `cargo fmt`, then re-check.
2. `cargo clippy --all-targets -- -D warnings`.
3. `cargo test`.

Report each step as pass or fail. For a failure, quote the first error with its `file:line`. Do not silence a lint with `#[allow]` unless the reason is written next to it.
