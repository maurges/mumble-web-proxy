{ pkgs ? import <nixpkgs> {}, ... }:

pkgs.rustPlatform.buildRustPackage rec {
  pname = "mumble-web-proxy";
  version = "v0.1.1";

  src = ./.;
  cargoHash = "sha256-gfb/0oLCofQtrF9KmKRaH5eYY5aCCyDDeY8mUAnQELY=";

  nativeBuildInputs = [
    pkgs.pkg-config
    pkgs.rustPlatform.bindgenHook
  ];

  buildInputs = [
    pkgs.openssl pkgs.glib pkgs.libnice
  ];

  meta = {
    description = "websocket/webrtc proxy for mumble protocol";
  };
}
