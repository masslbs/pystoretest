# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT
{
  description = "Mass Market Relay Testing";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    contracts.url = "github:masslbs/contracts/stage0";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    contracts,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        mass-python = import ./pythonenv.nix {
          inherit pkgs;
        };
        contracts_abi = contracts.packages.${system}.default;
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [mass-python pkgs.pyright pkgs.black pkgs.alejandra];
          shellHook = ''
            export $(egrep -v '^#' .env | xargs)
            export PYTHON=${mass-python}/bin/python
            export MASS_CONTRACTS=${contracts_abi}
          '';
        };

        packages.default = pkgs.stdenv.mkDerivation {
          name = "pystoretest";
          src = ./.;

          dontBuild = true;

          installPhase = ''
            mkdir -p $out/{tests,bin}

            cp *.py $out/tests/
            cp testcats.md $out/tests/

            # this is a bit of a hack
            # we need to copy the tests to a temp dir
            # because pytest doesn't like to run from read-only nix store
            # we also need to escape the sub-shell and variables
            # otherwise they will expanded in the installPhase context
            cat > $out/bin/pystoretest <<EOF
            #!/bin/sh
            set -e
            export MASS_CONTRACTS=${contracts_abi}
            rundir=\$(mktemp -d /tmp/pystoretest.XXXXXX)
            cp $out/tests/*.py \$rundir/
            cp $out/tests/testcats.md \$rundir/
            cd \$rundir
            exec ${mass-python}/bin/pytest "\$@"
            EOF
            chmod +x $out/bin/pystoretest
          '';
        };
      }
    );
}
