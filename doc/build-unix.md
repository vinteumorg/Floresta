# Building on Unix

## Prerequisites
```bash
sudo apt update
sudo apt install gcc build-essential pkg-config
```

You'll need Rust and Cargo, refer to [this](https://www.rust-lang.org/) for more details. Minimum support version is rustc 1.74 and newer.

## Building

Once you have Cargo, clone the repository with:

```bash
git clone https://github.com/vinteumorg/Floresta.git
```

go to the Floresta directory

```bash
cd Floresta/
```

and build with cargo build

```bash
cargo build --release

# Optionally, you can add florestad and floresta-cli to the path with
cargo install --path ./florestad
cargo install --path ./crates/floresta-cli
```

If you are using Nix, you can add Florestad to your system following the instructions [here](nix.md).
