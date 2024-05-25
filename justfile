_list:
    @just --list

clippy:
    cargo clippy --workspace --no-default-features
    cargo clippy --workspace --all-features
    cargo hack --feature-powerset --depth=3 clippy --workspace

test:
    cargo nextest run --all-features
    cargo test --doc --all-features
    @just test-coverage-codecov
    @just test-coverage-lcov
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

test-coverage-codecov:
    cargo llvm-cov --workspace --all-features --codecov --output-path codecov.json

test-coverage-lcov:
    cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info

doc *args:
    RUSTDOCFLAGS="--cfg=docsrs" cargo +nightly doc --no-deps --workspace --all-features {{ args }}

doc-watch: (doc "--open")
    cargo watch -- just doc

check:
    just --unstable --fmt --check
    fd --hidden --extension=md --extension=yml --exec-batch prettier --check
    fd --hidden --extension=toml --exec-batch taplo format --check
    fd --hidden --extension=toml --exec-batch taplo lint
    cargo +nightly fmt -- --check

fmt:
    just --unstable --fmt
    nix fmt
    fd --hidden --extension=md --extension=yml --exec-batch prettier --write
    fd --hidden --extension=toml --exec-batch taplo format
    cargo +nightly fmt
