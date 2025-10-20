{
  config,
  lib,
  pkgs,
  ...
}:

with lib;

let
  cfg = config.services.floresta;

  configFile = pkgs.writeText "floresta-config.toml" ''
    ${optionalString (cfg.wallet.xpubs != [ ]) ''
      [wallet]
      xpubs = ${builtins.toJSON cfg.wallet.xpubs}
    ''}
    ${optionalString (cfg.wallet.descriptors != [ ]) ''
      descriptors = ${builtins.toJSON cfg.wallet.descriptors}
    ''}
    ${optionalString (cfg.wallet.addresses != [ ]) ''
      addresses = ${builtins.toJSON cfg.wallet.addresses}
    ''}
    ${cfg.extraConfig}
  '';

  startScript = pkgs.writeShellScript "floresta-start" ''
    exec ${cfg.package}/bin/florestad \
      --network ${cfg.network} \
      --data-dir ${cfg.dataDir} \
      ${optionalString cfg.debug "--debug"} \
      ${optionalString cfg.noCfilters "--no-cfilters"} \
      ${optionalString cfg.noAssumeUtreexo "--no-assume-utreexo"} \
      ${optionalString cfg.noBackfill "--no-backfill"} \
      ${optionalString cfg.disableDnsSeeds "--disable-dns-seeds"} \
      ${optionalString (cfg.connect != null) "--connect ${cfg.connect}"} \
      ${optionalString (cfg.proxy != null) "--proxy ${cfg.proxy}"} \
      ${optionalString (cfg.assumeValid != null) "--assume-valid ${cfg.assumeValid}"} \
      ${optionalString (cfg.rpc.enable) "--rpc-address ${cfg.rpc.address}"} \
      ${optionalString (cfg.electrum.enable) "--electrum-address ${cfg.electrum.address}"} \
      ${optionalString (cfg.electrum.enableTls) "--enable-electrum-tls --electrum-address-tls ${cfg.electrum.tlsAddress}"} \
      ${
        optionalString (cfg.electrum.tlsCertPath != null) "--tls-cert-path ${cfg.electrum.tlsCertPath}"
      } \
      ${optionalString (cfg.electrum.tlsKeyPath != null) "--tls-key-path ${cfg.electrum.tlsKeyPath}"} \
      ${optionalString (cfg.electrum.generateCert) "--generate-cert"} \
      ${optionalString (cfg.zmq.enable) "--zmq-address ${cfg.zmq.address}"} \
      ${
        optionalString (
          cfg.filtersStartHeight != null
        ) "--filters-start-height ${toString cfg.filtersStartHeight}"
      } \
      ${optionalString cfg.allowV1Fallback "--allow-v1-fallback"} \
      --config-file ${configFile} \
      ${cfg.extraArgs}
  '';

in
{
  options.services.floresta = {
    enable = mkEnableOption "Floresta Bitcoin full node";

    package = mkOption {
      type = types.package;
      default = pkgs.florestad;
      defaultText = literalExpression "pkgs.florestad";
      description = "The Florestad package to use.";
    };

    network = mkOption {
      type = types.enum [
        "mainnet"
        "testnet"
        "signet"
        "regtest"
      ];
      default = "mainnet";
      description = "Bitcoin network to use.";
    };

    dataDir = mkOption {
      type = types.path;
      default = "$HOME/.floresta";
      description = "Directory to store blockchain data.";
    };

    user = mkOption {
      type = types.str;
      default = "florestad";
      description = "User account under which Floresta runs.";
    };

    debug = mkOption {
      type = types.bool;
      default = false;
      description = "Enable debug logging level.";
    };

    noCfilters = mkOption {
      type = types.bool;
      default = false;
      description = "Wheter to disable compact block filters features.";
    };

    noAssumeUtreexo = mkOption {
      type = types.bool;
      default = false;
      description = "Wheter to disable assume-utreexo optimization.";
    };

    noBackfill = mkOption {
      type = types.bool;
      default = false;
      description = "Disable backfilling of historical blocks.";
    };

    disableDnsSeeds = mkOption {
      type = types.bool;
      default = false;
      description = "Disable DNS seeds for peer discovery.";
    };

    connect = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:8333";
      description = "Connect to a specified peer.";
    };

    proxy = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "127.0.0.1:9050";
      description = "SOCKS5 proxy address.";
    };

    assumeValid = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5";
      description = "Assume-valid block hash for faster sync.";
    };

    allowV1Fallback = mkOption {
      type = types.bool;
      default = false;
      description = "Allow fallback to v1 P2P protocol.";
    };

    filtersStartHeight = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Block height to start building compact filters from.";
    };

    rpc = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable JSON-RPC server.";
      };

      address = mkOption {
        type = types.str;
        default = "127.0.0.1:8332";
        description = "JSON-RPC server listening address.";
      };
    };

    electrum = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Electrum server.";
      };

      address = mkOption {
        type = types.str;
        default = "127.0.0.1:50001";
        description = "Electrum server listening address.";
      };

      enableTls = mkOption {
        type = types.bool;
        default = false;
        description = "Enable TLS for Electrum server.";
      };

      tlsAddress = mkOption {
        type = types.str;
        default = "127.0.0.1:50002";
        description = "Electrum TLS server listening address.";
      };

      tlsCertPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to TLS certificate file.";
      };

      tlsKeyPath = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "Path to TLS private key file.";
      };

      generateCert = mkOption {
        type = types.bool;
        default = false;
        description = "Auto-generate self-signed TLS certificate.";
      };
    };

    zmq = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable ZMQ notifications.";
      };

      address = mkOption {
        type = types.str;
        default = "tcp://127.0.0.1:28332";
        description = "ZMQ server address.";
      };
    };

    wallet = {
      xpubs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "xpub6CUGRUonZSQ4TWtTMmzXdrXDtypWKiKrhko4egpiMZbpiaQL2jkwSB1icqYh2cfDfVxdx4df189oLKnC5fSwqPfgyP3hooxujYzAu3fDVmz"
        ];
        description = "Extended public keys for watch-only wallet.";
      };

      descriptors = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [
          "wpkh([d34db33f/84'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*)"
        ];
        description = "Output descriptors for watch-only wallet.";
      };

      addresses = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" ];
        description = "Bitcoin addresses to watch.";
      };
    };

    extraBuildArgs = mkOption {
      type = types.lines;
      default = "";
      description = ""
    };

    extraConfig = mkOption {
      type = types.lines;
      default = "";
      description = "Extra configuration to append to config.toml.";
    };

    extraArgs = mkOption {
      type = types.separatedString " ";
      default = "";
      description = "Extra command-line arguments to pass to florestad.";
    };

    openPorts = mkOption {
      type = types.bool;
      default = false;
      description = "Open firewall ports for P2P, RPC, and Electrum.";
    };
  };

  config = mkIf cfg.enable {
    networking.firewall = mkIf cfg.openFirewall {
      allowedTCPPorts =
        optional (cfg.network == "mainnet") 8333
        ++ optional (cfg.network == "testnet") 18333
        ++ optional (cfg.network == "signet") 38333
        ++ optional (cfg.network == "regtest") 18444;
    };

    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = cfg.dataDir;
      createHome = true;
      description = "Floresta Bitcoin node user";
    };

    users.groups.${cfg.group} = { };
    # Note: to be close as possible to /contrib/init/floresta.service
    systemd.services.floresta = {
      description = "Floresta: A Lightweight Utreexo-powered Bitcoin full node implementation";
      documentation = "https://github.com/vinteumorg/Floresta";
      after = [ "network-online.target time-set.target" ];
      wants = [ "network-online.target" ];
      # keeps running if user logs out.
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {

        Type = "forking";

        User = cfg.user;
        Group = cfg.group;
        
        ExecStartPre = "/bin/chgrp florestad /etc/florestad";
        
        ExecStart = startScript;
        
        Restart = "no";

        TimeoutStartSec = "infinity";
        TimeoutStopSec = "600s";

        PIDFile = "/run/florestad/florestad.pid";

        # /run/florestad
        RuntimeDirectory = "florestad";
        RuntimeDirectoryMode = "0710";

        # /etc/florestad
        ConfigurationDirectory = "florestad";
        ConfigurationDirectoryMode = "0710";

        # /var/lib/florestad
        StateDirectory = "florestad";
        StateDirectoryMode = "0710";

        # Provide a private /tmp and /var/tmp.
        PrivateTmp = true;

        # Mount /usr, /boot/ and /etc read-only for the process.
        ProtectSystem = "full";

        # Deny access to /home, /root and /run/user
        ProtectHome = true;

        # Disallow the process and all of its children to gain
        # new privileges through execve().
        NoNewPrivileges = true;

        # Use a new /dev namespace only populated with API pseudo devices
        # such as /dev/null, /dev/zero and /dev/random.
        PrivateDevices = true;

        # Deny the creation of writable and executable memory mappings.
        MemoryDenyWriteExecute = true;

        # Restrict ABIs to help ensure MemoryDenyWriteExecute is enforced
        SystemCallArchitectures = "native";
      };
    };
  };
}
