{ self }:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.drcom-client-cpp;
in
{
  options.services.drcom-client-cpp = {
    enable = lib.mkEnableOption "DRCOM campus network authentication";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
      description = "DRCOM client package to run.";
    };
    configFile = lib.mkOption {
      type = lib.types.str;
      default = "/etc/drcom.conf";
      description = "Absolute path to a private configuration file outside the Nix store.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.drcom-client-cpp = {
      description = "DRCOM campus network authentication";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/drcom_client -c ${lib.escapeShellArg cfg.configFile}";
        Restart = "on-abnormal";
        RestartSec = 5;
      };
    };
  };
}
