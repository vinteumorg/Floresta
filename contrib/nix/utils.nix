{ pkgs }:
{
  #set of reusable functions and variables trough the projects nix expressions.
  prepareBinariesScript =
    { binaries }:
    let
      _isListCheck = pkgs.lib.trivialthrowIfNot (pkgs.lib.isList binaries) "prepareBinariesScript expects a list of packages";
    in
    ''
      # Modified version of the prepare.sh script from the floresta project.
      # This script prepares the environment for functional tests using Nix-provided packages.

      HEAD_COMMIT_HASH=$(git rev-parse HEAD)
      export FLORESTA_TEMP_DIR="/tmp/floresta-temp-dir.$HEAD_COMMIT_HASH"

      mkdir -p "$FLORESTA_TEMP_DIR/binaries"

      # Generate symlink commands for each binary in the list

      ${pkgs.lib.lists.forEach binaries (binary: ''
        ln -s ${binary}/bin/${pkgs.lib.strings.getName binary} "$FLORESTA_TEMP_DIR/binaries/${pkgs.lib.strings.getName binary}"
      '')}
    '';

}
