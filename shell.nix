{ pkgs, contracts }: let
  ourPython = pkgs.python311;

  pyunormalize = ourPython.pkgs.buildPythonPackage rec {
    pname = "pyunormalize";
    version = "15.1.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-z0qHRRoPHLdpEaqX9DL0V54fVkovDITOSIxzpzkBtsE=";
    };
    buildInputs = [ pinnedPython.pkgs.setuptools ];
    # le sigh...
    postUnpack = ''
      sed -i 's/version=get_version()/version="${version}"/' ${pname}-${version}/setup.py
      sed -i 's/del _version//' ${pname}-${version}/${pname}/__init__.py
    '';
  };

  ckzg = ourPython.pkgs.buildPythonPackage rec {
    pname = "ckzg";
    version = "1.0.2";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-QpWsw4D41C6+pKSgpoxCSjIrszWjO60Fxy6tjLso0Rg=";
    };
    nativeBuildInputs = [ pkgs.clang ];
    buildInputs = [ pinnedPython.pkgs.setuptools ];
  };

  packageOverrides = self: super: {
    parsimonious = super.parsimonious.overridePythonAttrs (old: rec {
      pname = "parsimonious";
      version = "0.9.0";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-sq0a5jovZb149eCorFEKmPNgekPx2yqNRmNqXZ5KMME=";
      };
    });

    eth-account = super.eth-account.overridePythonAttrs (old: rec {
      pname = "eth-account";
      version = "0.11.2";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-tD2vLArkPyokunVNZoifBD+uTTURVZyybrASK66a+70=";
      };
      propagatedBuildInputs = super.eth-account.propagatedBuildInputs ++ [
        ckzg
        pinnedPython.pkgs.pydantic
        pinnedPython.pkgs.eth-keyfile
        pinnedPython.pkgs.hexbytes
      ];
    });

    web3 = super.web3.overridePythonAttrs (old: rec {
      pname = "web3";
      version = "6.20.1";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-opvBhjc04cBfEo3bxWh48pnqcXdoBuZntYGoO11b4O0";
      };
      propagatedBuildInputs = super.web3.propagatedBuildInputs ++ [
        pyunormalize
      ];
    });
  };

  pinnedPython = ourPython.override {
    inherit packageOverrides;
    self = ourPython;
  };

  massmarket_hash_event = pinnedPython.pkgs.buildPythonPackage rec {
    pname = "massmarket_hash_event";
    version = "2.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-9qnF6TZd4KUM5J1Lo1rgeLvTRSI4GRCEoeFz/tnaqdI";
    };
    # to test pre-releases run 'make build' in network-schema/python and update the path below
    # src = /home/cryptix/Mass/network-schema/python/dist/massmarket_hash_event-${version}.tar.gz;
    format = "pyproject";
    buildInputs = [
      pinnedPython.pkgs.setuptools
      pinnedPython.pkgs.setuptools-scm
      pkgs.protobuf
      pinnedPython.pkgs.web3
    ];
  };

   abnf = pinnedPython.pkgs.buildPythonPackage rec {
    pname = "abnf";
    version = "2.2.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-QzOA/TKFW7xgvHs9NdQGFuITg6Mu0cm4iT0W2fSmwvQ";
    };
    format = "pyproject";
    buildInputs = [
      pinnedPython.pkgs.setuptools
      pinnedPython.pkgs.setuptools-scm
    ];
   };

   siwe = pinnedPython.pkgs.buildPythonPackage rec {
     pname = "siwe";
     version = "4.0.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-j1sSBCszXCCPKrDOzOlVomAy7F/4q0J5Tjwqtjo83TM";
    };
    format = "pyproject";
    propagatedBuildInputs = [
      pinnedPython.pkgs.poetry-core
      pkgs.protobuf
      pinnedPython.pkgs.web3
      abnf
      pinnedPython.pkgs.pydantic
    ];
   };

  mass-python-packages = ps:
    with ps; [
      setuptools
      pytest
      websockets
      web3
      safe-pysha3
      siwe
      massmarket_hash_event
    ];
  mass-python = pinnedPython.withPackages mass-python-packages;

  contracts_abi = contracts.packages.${pkgs.system}.default;
in
  pkgs.mkShell {
    buildInputs = [mass-python pkgs.pyright];
    shellHook = ''
      export $(egrep -v '^#' .env | xargs)
      export PYTHON=${mass-python}/bin/python
      export MASS_CONTRACTS=${contracts_abi}
    '';
  }
