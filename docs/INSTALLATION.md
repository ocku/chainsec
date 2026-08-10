# Installation

`chainsec` is a single Rust binary. You can build it from source, run it with Docker, or install it with Cargo.

## Prerequisites

- **Rust toolchain**: Rust 1.89 or newer (the crate uses the 2024 edition). Install via [rustup](https://rustup.rs/):
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```
- **C toolchain**: a C compiler and linker are required to build the Tree-sitter grammars (`cc`/`clang` on Linux and macOS, MSVC on Windows).
- **Docker** (optional): only needed for the container image.

## Build from source

```sh
git clone https://github.com/ocku/chainsec
cd chainsec
cargo build --locked --release
```

The binary is written to `target/release/chainsec`. Optionally install it onto your `PATH`:

```sh
install -m 0755 target/release/chainsec /usr/local/bin/chainsec
```

## Install with Cargo

Directly from the repository:

```sh
cargo install --locked --git https://github.com/ocku/chainsec
```

Or from a local checkout:

```sh
cargo install --locked --path .
```

This places `chainsec` in `~/.cargo/bin`, which is typically already on your `PATH`.

## Docker

Build the image:

```sh
docker build -t chainsec .
```

The image runs as a non-root user with `/scan` as the working directory and `/cache` for the package cache. Mount the project you want to scan at `/scan`:

```sh
docker run --rm -v /path/to/project:/scan chainsec --max-depth 0
```

For online scans, also mount a cache directory and pass your network policy:

```sh
docker run --rm \
  -v /path/to/project:/scan \
  -v chainsec-cache:/cache \
  chainsec --online --allow-host pypi.org --allow-host files.pythonhosted.org
```

Note that the container has no network restrictions of its own; `chainsec`'s `--online`/`--allow-host` policy still governs outbound access.


## Verify the installation

```sh
chainsec --version
chainsec --help
```

Then run a local offline scan to confirm everything works:

```sh
chainsec --max-depth 0
```

## Next steps

- [Quick start](../README.md#quick-start) in the README
- [Configuration and CLI reference](CONFIGURATION.md)
- [Security model](SECURITY_MODEL.md)
