{
  description = "Mass Market Relay Testing";

  inputs  = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
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
