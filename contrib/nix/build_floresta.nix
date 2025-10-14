{
  pkgs ? import <nixpkgs>,
  src ? ../../.,
  packageName ? "all",
}:

let
  inherit (pkgs) lib;
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

  # This is the 1.90.0 rustup (and its components) toolchain from our `./rust-toolchain.toml`
  florestaRust = pkgs.rust-bin.fromRustupToolchainFile "${src}/rust-toolchain.toml";

  # This sets the rustc and cargo to the ones from the florestaRust.
  #
  # Defined in Flake.nix directly from the rust-toolchain.
  buildRustPackage = pkgs.rustPlatform.buildRustPackage.override {
    rustc = florestaRust;
    cargo = florestaRust;
  };

  # TLDR: this block below ensures to build the right component with the right flags to it.
  packageInfo =
    if packageName == "all" then
      {
        pname = "floresta";
        cargoBuildFlags = [ ]; # no need to specify flags
        description = "Floresta All";

        # We need to get a different toml for different packages
        #
        # Since we only use this introspection of Cargo.toml for getting package
        # version, this ones gets the version from florestad which is the one we
        # track major progress of the project.
        cargoToml = builtins.fromTOML (builtins.readFile "${src}/bin/florestad/Cargo.toml");
      }
    else if packageName == "libfloresta" then
      {
        pname = "libfloresta";
        cargoBuildFlags = [ "--lib" ]; # flag for compiling the lib of this workspace
        description = "Floresta library";

        # We need to get a different toml for different packages
        cargoToml = builtins.fromTOML (builtins.readFile "${src}/crates/floresta/Cargo.toml");
      }
    else if packageName == "florestad" then
      {
        pname = "${packageName}";
        cargoBuildFlags = [
          "--bin"
          "${packageName}"
        ]; # flag for compiling the florestad binary
        description = "Floresta daemon";

        # We need to get a different toml for different packages
        cargoToml = builtins.fromTOML (builtins.readFile "${src}/bin/florestad/Cargo.toml");
      }
    else if packageName == "floresta-cli" then
      {
        pname = "${packageName}";
        cargoBuildFlags = [
          "--bin"
          "${packageName}"
        ]; # flag for compiling the floresta-cli binary
        description = "Floresta CLI";

        # We need to get a different toml for different packages
        cargoToml = builtins.fromTOML (builtins.readFile "${src}/bin/floresta-cli/Cargo.toml");
      }
    else
      throw "Requested packageName '${packageName}' not found. Available packages: florestalib, florestad, floresta-cli and all (exports everything)";
in
buildRustPackage {
  inherit (packageInfo.cargoToml.package) version;
  inherit (packageInfo) pname cargoBuildFlags;
  inherit buildInputs src;

  doCheck = false; # we need to disable testing, it needs special setup.

  cargoLock = {
    lockFile = "${src}/Cargo.lock";
  };

  meta = with lib; {
    description = "A lightweight bitcoin full node; " + packageInfo.description;
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
