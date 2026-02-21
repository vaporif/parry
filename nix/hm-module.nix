{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkOption mkIf types;
  cfg = config.programs.parry;

  patternEntryType = types.submodule {
    options = {
      pattern = mkOption {
        type = types.str;
        description = "The pattern string to match.";
      };
      kind = mkOption {
        type = types.enum ["path_segment" "suffix" "substring"];
        default = "path_segment";
        description = "How the pattern is matched against paths.";
      };
    };
  };

  patternsType = types.submodule {
    options = {
      sensitive_paths = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf patternEntryType;
              default = [];
              description = "Sensitive path patterns to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in sensitive path patterns to remove.";
            };
          };
        };
        default = {};
      };
      exfil_domains = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Exfiltration domains to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in exfiltration domains to remove.";
            };
          };
        };
        default = {};
      };
      secrets = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Secret regex patterns to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in secret patterns to remove.";
            };
          };
        };
        default = {};
      };
    };
  };

  patternsToml = pkgs.writers.writeTOML "patterns.toml" {
    sensitive_paths = {
      add = map (e: {inherit (e) pattern kind;}) cfg.patterns.sensitive_paths.add;
      remove = cfg.patterns.sensitive_paths.remove;
    };
    exfil_domains = {
      add = cfg.patterns.exfil_domains.add;
      remove = cfg.patterns.exfil_domains.remove;
    };
    secrets = {
      add = cfg.patterns.secrets.add;
      remove = cfg.patterns.secrets.remove;
    };
  };

  envVars =
    lib.optional (cfg.threshold != null) ''--set PARRY_THRESHOLD "${toString cfg.threshold}"''
    ++ lib.optional (cfg.logLevel != null) ''--set PARRY_LOG "${cfg.logLevel}"''
    ++ lib.optional (cfg.hfToken != null) ''--set HF_TOKEN "${cfg.hfToken}"''
    ++ lib.optional (cfg.hfTokenFile != null) ''--set HF_TOKEN_PATH "${cfg.hfTokenFile}"'';

  wrappedParry =
    if envVars != []
    then
      pkgs.symlinkJoin {
        name = "parry-wrapped";
        paths = [cfg.package];
        nativeBuildInputs = [pkgs.makeWrapper];
        postBuild = ''
          wrapProgram $out/bin/parry ${lib.concatStringsSep " " envVars}
        '';
      }
    else cfg.package;
in {
  options.programs.parry = {
    enable = mkEnableOption "parry prompt injection scanner";

    package = mkOption {
      type = types.package;
      description = "The parry package to use.";
    };

    threshold = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "ML detection threshold (0.0–1.0). Null uses the default (0.5).";
    };

    logLevel = mkOption {
      type = types.nullOr (types.enum ["trace" "debug" "info" "warn" "error"]);
      default = null;
      description = "Log level filter for tracing output.";
    };

    hfToken = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "HuggingFace token. Prefer hfTokenFile for secrets.";
    };

    hfTokenFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a file containing the HuggingFace token.";
    };

    patterns = mkOption {
      type = types.nullOr patternsType;
      default = null;
      description = "Custom patterns config. When set, generates ~/.config/parry/patterns.toml.";
    };
  };

  config = mkIf cfg.enable {
    home.packages = [wrappedParry];

    xdg.configFile."parry/patterns.toml" = mkIf (cfg.patterns != null) {
      source = patternsToml;
    };
  };
}
