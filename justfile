default:
    @just --list

build:
    cargo build --workspace

check:
    cargo clippy --workspace
    cargo test --workspace

test:
    cargo test --workspace

clippy:
    cargo clippy --workspace

# Build with ONNX auto-download backend
build-onnx:
    cargo build --workspace --no-default-features --features onnx-fetch

# Run scan on stdin
scan:
    cargo run -- scan

# Start daemon
serve:
    cargo run -- serve

