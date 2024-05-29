{
  description = "Mass Market Relay Testing";

  inputs  = {
    flake-utils.url = "github:numtide/flake-utils";
    contracts.url = "github:masslbs/contracts";
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
      in {
        devShells.default = import ./shell.nix {
          inherit pkgs;
          inherit contracts;
        };
      }
    );
}
