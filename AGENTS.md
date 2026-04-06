# Repository Guidelines

## Project Structure & Module Organization
`tonel` is a Rust crate with two CLI binaries: `src/bin/client.rs` (`tonelc`) and `src/bin/server.rs` (`tonels`). Shared logic lives in `src/lib.rs`, transport code is under `src/tcp/`, and general helpers are in `src/utils.rs`. CI definitions live in `.github/workflows/`. There is no top-level `tests/`, `examples/`, or asset directory today; existing unit tests are embedded in the library.

## Build, Test, and Development Commands
Use Cargo for all local workflows:

- `cargo build` builds the library and both binaries in debug mode.
- `cargo build --release` produces optimized `tonelc` and `tonels`.
- `cargo test` runs the in-tree unit tests from `src/lib.rs`.
- `cargo clippy --verbose` matches the lint step used in GitHub Actions.
- `cargo run --bin tonelc -- --help` or `cargo run --bin tonels -- --help` checks CLI behavior quickly.

Optional allocator features are exposed through Cargo features, for example `cargo build --release --features alloc-mi`.

## Coding Style & Naming Conventions
Follow standard Rust style and keep code `rustfmt`-compatible, using 4-space indentation. Use `snake_case` for modules, functions, and variables, `PascalCase` for types and enums, and `UPPER_SNAKE_CASE` for constants such as socket deadlines. Keep modules focused: protocol packet changes belong in `src/tcp/packet.rs`, while reusable helpers should stay in `src/lib.rs` or `src/utils.rs`.

## Testing Guidelines
Add unit tests next to the code they validate with `#[cfg(test)]` when possible, following the pattern already used in `src/lib.rs`. Name tests for the behavior being verified, such as `xor_encryption_with_max_key`. For protocol or CLI changes, include both success-path and edge-case coverage. Run `cargo test` before opening a PR.

## Commit & Pull Request Guidelines
Recent history uses short, imperative summaries like `updated deps` alongside release tags such as `v0.6.1`. Keep commit subjects brief and specific. Pull requests should explain the networking impact, note any Linux/macOS differences, and list the commands you ran locally. Include sample CLI output or config snippets when changing flags, defaults, or TUN behavior.

## Security & Configuration Notes
This project manages sockets, firewalls, and TUN interfaces. Avoid committing real keys, handshake payloads, or environment-specific interface names. Document any requirement for elevated privileges, `setcap`, or firewall rules in the PR description when behavior changes.
