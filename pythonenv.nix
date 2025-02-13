{pkgs}: let
  ourPython = pkgs.python313;

  pinnedPython = ourPython.override {
    inherit packageOverrides;
    self = ourPython;
  };

  pyunormalize = ourPython.pkgs.buildPythonPackage rec {
    pname = "pyunormalize";
    version = "15.1.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-z0qHRRoPHLdpEaqX9DL0V54fVkovDITOSIxzpzkBtsE=";
    };
    buildInputs = [pinnedPython.pkgs.setuptools];
    # le sigh...
    postUnpack = ''
      sed -i 's/version=get_version()/version="${version}"/' ${pname}-${version}/setup.py
      sed -i 's/del _version//' ${pname}-${version}/${pname}/__init__.py
    '';
  };

  packageOverrides = self: super: {
    parsimonious = super.parsimonious.overridePythonAttrs (old: rec {
      pname = "parsimonious";
      version = "0.10.0";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-goFgDaGA7IrjVCekq097gr/sHj0eUvgMtg6oK5USUBw=";
      };
    });

    asn1tools = super.asn1tools.overridePythonAttrs (old: rec {
      pname = "asn1tools";
      version = old.version;
      src = old.src;
      doCheck = false; # TODO: just on darwin..?
    });

    eth-keys = super.eth-keys.overridePythonAttrs (old: rec {
      pname = "eth-keys";
      version = "0.6.1";
      src = self.fetchPypi {
        inherit version;
        pname = "eth_keys";
        sha256 = "sha256-pD4mPLyr/WL6dpFo78bCex9WAwQOTeIruE0SVn5P2WI=";
      };
      doCheck = false;
    });

    eth-account = super.eth-account.overridePythonAttrs (old: rec {
      pname = "eth-account";
      version = "0.13.4";
      src = self.fetchPypi {
        inherit version;
        pname = "eth_account";
        sha256 = "sha256-Lh8t4kC+89nz2AE2VhNdKnm2vm1OeIW86crOQzSko3Y=";
      };
      propagatedBuildInputs =
        super.eth-account.propagatedBuildInputs
        ++ [
          pinnedPython.pkgs.pydantic
        ];
      doCheck = false;
    });

    websockets = super.websockets.overridePythonAttrs (old: rec {
      pname = "websockets";
      version = "13.1";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-o7M2YIfBvAonlREe3K3duLO1lQnV211+o/3Wn5VKiHg=";
      };
      doCheck = false;
    });

    web3 = super.web3.overridePythonAttrs (old: rec {
      pname = "web3";
      version = "7.8.0";
      src = self.fetchPypi {
        inherit pname version;
        sha256 = "sha256-cSvJ/Wse9uRn7iTCW1geGVHKssuhf59UjxJYdzTyyFc=";
      };
      propagatedBuildInputs =
        super.web3.propagatedBuildInputs
        ++ [
          pyunormalize
        ];
      doCheck = false;
    });
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
    version = "4.4.0";
    src = ourPython.pkgs.fetchPypi {
      inherit pname version;
      hash = "sha256-X9+EMlOpHXgIXx2hHtfJaVu7dD4RLaZY5jooXd8//sc";
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

  massmarket = pinnedPython.pkgs.buildPythonPackage rec {
    pname = "massmarket";
    version = "4.0";
    # src = pkgs.python3.pkgs.fetchPypi {
    #   inherit pname version;
    #   hash = "sha256-vc9oSq7wt9s+qLSJTuhTAw4TFHmtBTGh5VGkSgPX7cQ=";
    # };
    # to test pre-releases run 'make build' in network-schema/python and update the path below
    src = ./massmarket-4.0-pre.tar.gz;
    format = "pyproject";
    buildInputs = [
      pinnedPython.pkgs.setuptools
      pinnedPython.pkgs.setuptools-scm
      pkgs.protobuf
      pinnedPython.pkgs.web3
    ];
  };

  mass-python-packages = ps:
    with ps; ([
        setuptools
        pytest
        pytest-timeout
        pytest-xdist
        pytest-repeat
        pytest-random-order
        pytest-benchmark
        factory-boy
        humanize
        websockets
        web3
        safe-pysha3
        filelock
        cbor2
        xxhash
      ]
      ++ [
        siwe
        massmarket
      ]);
in pinnedPython.withPackages mass-python-packages
