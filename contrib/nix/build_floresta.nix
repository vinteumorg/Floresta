{
  pkgs,
  florestaSrc ? ../../.,
}:

let
  # Pname defines the name of the package and will decide the output of this expression
  pname = "floresta-node";
  version = "0.7.0";

  lib = pkgs.lib;
  # This are deps needed to run and build rust projects.
  basicDeps = [
    pkgs.openssl
    pkgs.pkg-config
  ];

  # Here we set system related deps, checking if we are building for a Darwin device
  # libsDarwin are the necessary deps that are needed to build the floresta project for Darwin devices (?)
  buildInputs =
    if pkgs.system == "x86_64-darwin" || pkgs.system == "aarch64-darwin" then
      basicDeps ++ [ pkgs.darwin.apple_sdk.frameworks.Security ]
    else
      basicDeps;

  # This is the 1.74.1 rustup (and its components) toolchain from our `./rust-toolchain.toml`
  florestaRust = pkgs.rust-bin.fromRustupToolchainFile "${florestaSrc}/rust-toolchain.toml";

  # This sets the rustc and cargo to the ones from the florestaRust.
  #
  # Defined in Flake.nix directly from the rust-toolchain.
  buildRustPackage = pkgs.rustPlatform.buildRustPackage.override {
    rustc = florestaRust;
    cargo = florestaRust;
  };
in
buildRustPackage {
  inherit pname version;

  doCheck = false;

  src = "${florestaSrc}";

  cargoLock = {
    lockFile = "${florestaSrc}/Cargo.lock";
  };

  inherit buildInputs;

  meta = with lib; {
    description = "A lightweight bitcoin full node";
    homepage = "https://github.com/vinteumorg/Floresta";
    license = licenses.mit;
    maintainers = [ maintainers.jaoleal ];
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ];
  };
}
