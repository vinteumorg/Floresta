{ lib, rustPlatform, florestaRust, buildInputs }:

let
    # Pname defines the name of the package and will decide the output of this expression
    pname = "floresta-node";
    version = "0.6.0";

    # This sets the rustc and cargo to the ones from the florestaRust.
    #
    # Defined in Flake.nix directly from the rust-toolchain.
    buildRustPackage = rustPlatform.buildRustPackage.override {
        rustc = florestaRust;
        cargo = florestaRust;
    };
in
buildRustPackage {
  inherit pname version;

  doCheck = false;

  src = ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "bitcoin-0.31.0" = "sha256-2v87cb+Wd4OhgDG45Za3bxumaY7QKdw7nKuqKrmtHMs=";
    };
  };

  inherit buildInputs;

  meta = with lib; {
    description = "A lightweight bitcoin full node";
    homepage = "https://github.com/vinteumorg/Floresta";
    license = licenses.mit;
    maintainers = [ maintainers.Davidson maintainers.jaoleal ];
    platforms = [ "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin" ];
  };
}
