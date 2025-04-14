{ pkgs, ... }:
{
  # Set of reusable functions and variables trough the projects nix expressions.

  # This function make the needed setup for a functional FLORESTA_TEMP_DIR, creating
  # the needed directories and exporting the FLORESTA_TEMP_DIR variable. Its input is
  # a list of packages thatll be linked to the FLORESTA_TEMP_DIR/binaries and a String
  # which is expected to be the commit hash of HEAD.
  #
  # Input Set example:
  #
  # binariesToLink = [ package1 package2 ... ]
  # gitRev = "commit-hash"
  #
  # Itll go after binaries by its name and will not link it right if the name of the package
  # is not the same as the name of the binary.
  prepareBinariesScript =
    { binariesToLink, gitRev }:
    ''
      # Modified version of the prepare.sh script from the floresta project.
      # This script prepares the environment for functional tests using Nix-provided packages.

      HEAD_COMMIT_HASH=${gitRev}
      export FLORESTA_TEMP_DIR="/tmp/floresta-temp-dir.$HEAD_COMMIT_HASH"

      mkdir -p "$FLORESTA_TEMP_DIR/binaries"

      # Generate symlink commands for each binary in the list

      ${toString (
        pkgs.lib.lists.forEach binariesToLink (binary: ''
          ln -s ${binary}/bin/${pkgs.lib.strings.getName binary} "$FLORESTA_TEMP_DIR/binaries/${pkgs.lib.strings.getName binary}"
        '')
      )}
    '';

}
