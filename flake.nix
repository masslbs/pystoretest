# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT
{
  description = "Mass Market Relay Testing";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    contracts.url = "github:masslbs/contracts";
    network-schema.url = "github:masslbs/network-schema/v5-dev";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    contracts,
    network-schema,
  }:
    flake-utils.lib.eachDefaultSystem
    (
      system: let
        pkgs = nixpkgs.legacyPackages.${system};
        # Use the mass-python from network-schema as base and add extra packages
        base-python = network-schema.packages.${system}.mass-python;
        contracts_abi = contracts.packages.${system}.default;

        # Build extra packages for massmarket-client (only ones not already in massmarket)
        extraPackages = with base-python.pkgs; let
          abnf = buildPythonPackage rec {
            pname = "abnf";
            version = "2.2.0";
            format = "pyproject";
            src = fetchPypi {
              inherit pname version;
              hash = "sha256-QzOA/TKFW7xgvHs9NdQGFuITg6Mu0cm4iT0W2fSmwvQ";
            };
            buildInputs = [setuptools setuptools-scm];
          };

          siwe = buildPythonPackage rec {
            pname = "siwe";
            version = "4.4.0";
            format = "pyproject";
            src = fetchPypi {
              inherit pname version;
              hash = "sha256-X9+EMlOpHXgIXx2hHtfJaVu7dD4RLaZY5jooXd8//sc";
            };
            buildInputs = [web3];
            propagatedBuildInputs = [poetry-core pydantic abnf] ++ [pkgs.protobuf];
          };
        in [
          abnf
          siwe
          safe-pysha3
          humanize
          filelock
        ];

        # Python package derivation for massmarket-client
        massmarket-client-python = base-python.pkgs.buildPythonPackage rec {
          pname = "massmarket-client";
          version = "5.0.0";
          format = "pyproject";
          src = ./.;

          nativeBuildInputs = with base-python.pkgs; [setuptools setuptools-scm];
          propagatedBuildInputs = with base-python.pkgs;
            [
              network-schema.packages.${system}.massmarket-python
            ]
            ++ extraPackages;

          SETUPTOOLS_SCM_PRETEND_VERSION = version;

          pythonImportsCheck = ["massmarket_client"];
          nativeCheckInputs = with base-python.pkgs; [
            pytest
            pytest-timeout
            pytest-xdist
            pytest-repeat
            pytest-random-order
            pytest-benchmark
            factory-boy
          ];

          # Skip tests during build - they require external services
          doCheck = false;

          meta = with pkgs.lib; {
            description = "Python client for interacting with Mass Market relay services";
            license = licenses.mit;
          };
        };

        # Create enhanced Python environment with massmarket-client included
        enhanced-python = base-python.withPackages (ps:
          with ps;
            [
              pytest
              pytest-timeout
              pytest-xdist
              pytest-repeat
              pytest-random-order
              pytest-benchmark
              factory-boy
              # Packaging tools
              build
              twine
              setuptools
              setuptools-scm
              wheel
            ]
            ++ extraPackages ++ [massmarket-client-python]);

        pystoretest = pkgs.stdenv.mkDerivation {
          name = "pystoretest";
          src = ./.;

          dontBuild = true;

          nativeCheckInputs = [enhanced-python];

          installPhase = ''
            mkdir -p $out/{tests,bin}

            cp tests/*.py $out/tests/
            cp testcats.md $out/

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
            mkdir -p \$rundir/tests
            cp $out/tests/*.py \$rundir/tests/
            cp $out/testcats.md \$rundir/
            cd \$rundir
            exec ${enhanced-python}/bin/pytest "\$@"
            EOF
            chmod +x $out/bin/pystoretest
          '';

          installCheckPhase = ''
            echo "🔍 Validating testrunner can discover tests..."

            # Test the actual installed testrunner script
            echo "Running installed testrunner with --collect-only..."
            output=$($out/bin/pystoretest --collect-only -q 2>&1)

            # Check that tests were collected
            if echo "$output" | grep -q "tests collected"; then
              test_count=$(echo "$output" | grep "tests collected" | sed 's/.*\([0-9]*\) tests collected.*/\1/')
              echo "✅ Found $test_count tests"
            else
              echo "❌ No tests collected - output was:"
              echo "$output"
              exit 1
            fi

            # Verify specific test files are discovered
            expected_tests=("test_events.py" "test_currencies.py" "test_guests.py" "test_orders.py" "test_persistence.py" "test_registration.py" "test_benchmark.py" "test_compatibility.py" "test_connections.py")

            for test_file in "''${expected_tests[@]}"; do
              if echo "$output" | grep -q "$test_file"; then
                echo "✅ Found $test_file"
              else
                echo "❌ Missing $test_file in test discovery"
                exit 1
              fi
            done

            echo "✅ Testrunner validation successful - all expected tests discovered"
          '';

          doInstallCheck = true;
        };
      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [enhanced-python pkgs.pyright pkgs.black pkgs.alejandra pkgs.reuse];
          shellHook = ''
            export $(egrep -v '^#' .env | xargs)
            export PYTHON=${enhanced-python}/bin/python
            export MASS_CONTRACTS=${contracts_abi}
          '';
        };

        packages = {
          default = massmarket-client-python;
          massmarket-client-python = massmarket-client-python;
          enhanced-python = enhanced-python; # Expose the Python environment
          pystoretest = pystoretest; # Keep the test runner for backwards compatibility
        };
      }
    );
}
