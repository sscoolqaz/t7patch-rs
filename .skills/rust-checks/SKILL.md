---
name: rust-checks
description: Run this repo's formatting, clippy and test gates and report the result. Use before committing or when asked to check the Rust code.
---

# rust-checks

Run from the repo root. These are the gates listed in `AGENTS.md`, and the
same ones `.githooks/pre-commit` runs.

1. `cargo fmt --all --check`. If it fails, run `cargo fmt --all`, then re-check.
2. `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings`.
3. `cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings`.
4. Tests. On Linux:
   `CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --workspace --target x86_64-pc-windows-gnu`.
   On Windows: `cargo test --workspace`.

Steps 2 and 3 need both targets installed (`rustup target add <triple>`). If
the checkout is shared with other work, point `CARGO_TARGET_DIR` at a scratch
directory so the builds do not collide.

Report each step as pass or fail. For a failure, quote the first error with
its `file:line`. Do not silence a lint with `#[allow]` or `#[rustfmt::skip]`:
the only crate-wide allow is `unreadable_literal`, for IDA-style addresses.
