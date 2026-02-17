# List available recipes
default:
    @just --list

# Run all checks
check: clippy test check-fmt lint-toml check-typos lint-actions

# Format all
fmt: fmt-rust fmt-toml

# Build workspace
build:
    cargo build --workspace

# Build with ONNX auto-download backend
build-onnx:
    cargo build --workspace --no-default-features --features onnx-fetch

# Run clippy
clippy:
    cargo clippy --workspace -- -D warnings

# Run tests
test:
    cargo test --workspace

# Check Rust formatting
check-fmt:
    cargo fmt --all -- --check

# Format Rust code
fmt-rust:
    cargo fmt --all

# Lint TOML files
lint-toml:
    taplo check

# Format TOML files
fmt-toml:
    taplo fmt

# Check for typos
check-typos:
    typos

# Lint GitHub Actions
lint-actions:
    actionlint

# Run scan on stdin
scan:
    cargo run -- scan

# Start daemon
serve:
    cargo run -- serve

# Set up git hooks
setup-hooks:
    git config core.hooksPath .githooks
