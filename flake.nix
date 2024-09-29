{
  description = "Mumble web proxy";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }: flake-utils.lib.eachDefaultSystem (system:
    let pkgs = nixpkgs.legacyPackages.${system};
    in {
      packages = rec {
        mumble-web-proxy = import ./default.nix {inherit pkgs;};
        default = mumble-web-proxy;
      };
    }
  );
}
