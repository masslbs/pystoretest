{ pkgs, contracts }: let
  # web3 needs parsimonious v0.9.0
  # https://github.com/ethereum/web3.py/issues/3110#issuecomment-1737826910
  packageOverrides = self: super: {
    parsimonious = super.parsimonious.overridePythonAttrs (old: rec {
      pname = "parsimonious";
      version = "0.9.0";
      src = pkgs.python3.pkgs.fetchPypi {
        inherit pname version;
        sha256 = "sha256-sq0a5jovZb149eCorFEKmPNgekPx2yqNRmNqXZ5KMME=";
      };
      doCheck = false;
    });
  };

  pinnedPython = pkgs.python3.override {
    inherit packageOverrides;
    self = pkgs.python3;
  };

  massmarket_hash_event = pkgs.python3Packages.buildPythonPackage rec {
    pname = "massmarket_hash_event";
    version = "0.0.12a2";
    src = pkgs.python3.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-T3gG94vljHLLqQqFtCOx5MwLUwlNeQsTymE2DYnmCLw=";
    };
    #src = /home/cryptix/Mass/network-schema/python/dist/massmarket_hash_event-0.0.12a2.tar.gz;
    format = "pyproject";
    buildInputs = [
      pkgs.python3Packages.setuptools
      pkgs.python3Packages.setuptools-scm
      pkgs.protobuf
      pkgs.python3Packages.web3
    ];
    doCheck = false;
  };

  mass-python-packages = ps:
    with ps; [
      setuptools
      pytest
      websockets
      web3
      safe-pysha3
      massmarket_hash_event
    ];
  mass-python = pinnedPython.withPackages mass-python-packages;
  contracts_abi = contracts.packages.${pkgs.system}.default;
in
  pkgs.mkShell {
    buildInputs = [mass-python];
    shellHook = ''
      export $(egrep -v '^#' .env | xargs)
      export MASS_CONTRACTS=${contracts_abi}
    '';
  }
