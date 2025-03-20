{ pkgs ? import <nixpkgs>, src }:
pkgs.buildGoModule {
  pname = "utreexod";
  version = "0.4.1";
  vendorHash = "sha256-gZADkexHFUqcPVN7ImV9E8h/K/DgmL1CqMWUY2t8lDM=";
  inherit src;
}
