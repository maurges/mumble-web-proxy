{ config, lib, pkgs, ... }:

let
  mumble-web-proxy = import (pkgs.fetchgit {
    url = "https://github.com/maurges/mumble-web-proxy";
    deepClone = false;
    leaveDotGit = false;
    rev = "2896f6b08d85e5ad2eb7fae861f8630e81186ef2";
    hash = "sha256-mNL7XF9f0bnhBssKrX3wYOwVqxRtF3qv/+jKnG+BTPI=";
  }) { inherit pkgs; };

  cfg = config.services.mumble-web-proxy;
in {
  options.services.mumble-web-proxy = {
    enable = lib.mkEnableOption "mumble-web-proxy";

    port = lib.mkOption {
      type = lib.types.port;
      default = 64737;
      description = lib.mdDoc ''
        TCP port to listen on
      '';
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "localhost:64738";
      example = "example.com";
      description = lib.mdDoc ''
        Hostname and (optionally) port of the upstream Mumble server
      '';
    };

    acceptInvalidCertificate = lib.mkOption {
      type = lib.types.bool;
      default = false;
      example = true;
      description = lib.mdDoc ''
        Connect to upstream server even when its certificate is invalid. Only
        ever use this if know that your server is using a self-signed
        certificate!
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = {
      mumble-web-proxy = {
        group = "mumble-web-proxy";
        createHome = false;
        description = "mumble-web-proxy user";
        isNormalUser = false;
        isSystemUser = true;
      };
    };
    users.groups.mumble-web-proxy = {};

    systemd.packages = [mumble-web-proxy];

    systemd.services.mumble-web-proxy = {
      description = "Mumble web proxy websocket -> mumble-proto";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        User = "mumble-web-proxy";
        Group = "mumble-web-proxy";
        ExecStart = ''${mumble-web-proxy}/bin/mumble-web-proxy \
          ${if cfg.acceptInvalidCertificate then "--accept-invalid-certificate" else ""} \
          --listen-ws ${toString cfg.port} \
          --server ${cfg.host}
        '';

        Restart = "on-failure";
        StandardOutput = "journal";
        StandardError = "journal";
      };
    };
  };
}
