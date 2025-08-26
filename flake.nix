# SPDX-FileCopyrightText: 2025 Mass Labs
#
# SPDX-License-Identifier: MIT
{
  description = "Mass Market Relay Testing";

  inputs = {
    systems.url = "github:nix-systems/default";
    flake-parts.url = "github:hercules-ci/flake-parts";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nixpkgs.follows = "network-schema/nixpkgs"; # align python versions
    # mass things
    contracts.url = "github:masslbs/contracts/Order-Payments";
    network-schema.url = "github:masslbs/network-schema/new-payment-binding";
  };

  outputs = inputs @ {
    flake-parts,
    systems,
    contracts,
    network-schema,
    pre-commit-hooks,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = import systems;
      imports = [
        inputs.pre-commit-hooks.flakeModule
      ];
      perSystem = {
        pkgs,
        system,
        config,
        ...
      }: let
        contracts_abi = contracts.packages.${system}.default;

        # Build extra packages for massmarket-client (only ones not already in network-schema)
        extraPackages = with python-env.pkgs; let
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

        schema-package = network-schema.packages.${system}.python-package;

        pystoretest-deps = ps:
          with ps;
            [
              pytest-timeout
              pytest-xdist
              pytest-repeat
              pytest-random-order
              pytest-benchmark
              factory-boy
            ]
            ++ extraPackages
            ++ [network-schema.packages.${system}.massmarket-python];

        # Use the mass-python from network-schema as base and add extra packages
        build-env = network-schema.lib.makePythonEnvironment {
          inherit pkgs;
          additionalPackages = pystoretest-deps;
        };

        # Python package derivation for massmarket-client
        massmarket-client-python = build-env.pkgs.buildPythonPackage rec {
          pname = "massmarket-client";
          version = "5.0.0";
          format = "pyproject";
          src = ./.;

          nativeBuildInputs = with python-env.pkgs; [setuptools setuptools-scm];
          propagatedBuildInputs = pystoretest-deps python-env.pkgs;

          SETUPTOOLS_SCM_PRETEND_VERSION = version;

          # Generate contracts.py during build
          preBuild = ''
            export MASS_CONTRACTS=${contracts_abi}
            ${build-env}/bin/python generate_contracts.py
          '';

          pythonImportsCheck = ["massmarket_client"];
          nativeCheckInputs = with python-env.pkgs; [
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
        python-env = network-schema.lib.makePythonEnvironment {
          inherit pkgs;
          additionalPackages = ps: [massmarket-client-python];
        };

        pystoretest = pkgs.stdenv.mkDerivation {
          name = "pystoretest";
          src = ./.;

          dontBuild = true;

          nativeCheckInputs = [python-env];

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
            rundir=\$(mktemp -d /tmp/pystoretest.XXXXXX)
            mkdir -p \$rundir/tests
            cp $out/tests/*.py \$rundir/tests/
            cp $out/testcats.md \$rundir/
            cd \$rundir

            exec ${python-env}/bin/pytest "\$@"
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

          doInstallCheck = false;
        };
      in {
        pre-commit = {
          check.enable = true;
          settings = {
            src = ./.;
            hooks = {
              alejandra.enable = true;
              typos.enable = true;
              ruff.enable = true;
              ruff-format.enable = true;
            };
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs =
            [python-env pkgs.pyright pkgs.alejandra pkgs.reuse pkgs.ruff]
            ++ config.pre-commit.settings.enabledPackages;
          shellHook = ''
            ${config.pre-commit.settings.installationScript}
            export $(egrep -v '^#' .env | xargs)
            export PYTHON=${python-env}/bin/python
            export MASS_CONTRACTS=${contracts_abi}

            # Generate contracts.py when entering shell
            echo "Generating contracts.py from $MASS_CONTRACTS..."
            python generate_contracts.py
            echo "contracts.py generated successfully"
          '';
        };

        packages = {
          inherit massmarket-client-python python-env pystoretest;
          default = massmarket-client-python;
        };
      };
    };
}
