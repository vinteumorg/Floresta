#!/usr/bin/env bash

# Some necessary global variables
if [ $(id -u) == "0" ]; then
  me=$(who am i | awk '{print $1}')
else
  me=$(whoami)
fi

defaultRepo="vinteumorg"
defaultTag="0.7.0"
tarSrc="https://github.com/$defaultRepo/Floresta/archive/refs/tags/$defaultTag.tar.gz"
bdlDir=/tmp/Floresta-$defaultTag
tarDest=$bdlDir.tar.gz
florestaDir=/var/lib/florestad
florestaLib=/etc/florestad
florestaRun=/run/florestad
distribution=$(lsb_release -sc)
architecture=$(dpkg --print-architecture)

# use stable rust toolchain
export RUSTUP_TOOLCHAIN=stable
export CARGO_TARGET_DIR=$bdlDir/target

# CLI options
wallet_xpub=""
wallet_descriptor=""
assume_utreexo=false
enable_ssl=false
network="bitcoin"

show_usage () {
  echo "Install florestad and floresta_cli in your system and properly create a systemd service"
  echo ""
  echo "Usage:"
  echo "  install.sh [-opt <arg?>]..."
  echo ""
  echo "  -h           Show this message."
  echo "  -x <XPUB>    Define a xpub to be loaded onto config.toml."
  echo "  -d <DESC>    Define a descriptor to be loaded onto config.toml."
  echo "  -n <NETWORK> Pass --network onto built service (bitcoin, signet, testnet, regtest)."          
  echo "  -u           Pass --assume-utreexo onto built service."
  echo "  -s           Enable ssl into Floresta electrum server."
  echo "               This will create openssl key and certificate."
  echo ""
}

# Parse CLI options
while getopts ":x:d:n:ush" opt; do
  case $opt in
    x)
      wallet_xpub="$OPTARG"
      ;;
    d)
      wallet_descriptor="$OPTARG"
      ;;
    n)
      network="$OPTARG"
      ;;
    u)
      assume_utreexo=true
      ;;
    s)
      enable_ssl=true
      ;;
    h)
      show_usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

echo "🐧 Installing floresta for $me"

# Validate network option
valid_networks=("bitcoin" "signet" "testnet" "regtest")
if [[ ! " ${valid_networks[@]} " =~ " ${network} " ]]; then
  echo "❌ Invalid network '$network'. Valid options are: ${valid_networks[*]}"
  exit 1
fi

# Check for missing packages (currently, only debian-like)
# TODO: verify for fedora, arch and other systems
apt_install() {
  local missing=()

  for package in "$@"; do
    if ! dpkg -l | grep -q "^ii.*$package"; then
      missing+=("$package")
    fi
  done

  # Install curl first
  sudo apt-get install -y -q curl

  # Install missing packages if any
  if [ ${#missing[@]} -gt 0 ]; then
    echo "🐧 The following packages are missing: ${missing[*]}"
    echo "🐧 Updating package lists..."
    sudo apt update
    echo "🐧 Installing missing packages..."
    sudo apt-get install -y -q "${missing[@]}"
  else
    echo "🐧 All packages installed: skip"
  fi
}

# Install rustup with the recommended procedure (https://sh.rustup.rs)
install_rustup() {
  echo "🦀 Checking for rustup."
  haveRust=$(which rustup)
  if [ -z "$haveRust" ]; then
    echo "🦀 Rustup not found. Installing..."
    export RUSTUP_HOME=/home/$me/.rustup
    export CARGO_HOME=/home/$me/.cargo
    export PATH=/home/$me/.cargo/bin:$PATH
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y --no-modify-path

    # If this script run with sudo, it will will make '.cargo'
    # dir be owned by root. Change recursively this so the user will be the owner
    chown $me:$me -R /home/$me/.cargo

    # Load it on profile
    echo "source /home/$me/.cargo/env" >> /home/$me/.profile
    source /home/$me/.cargo/env
  else
    echo "🦀 Rustup found in $haveRust. Skip download..."
  fi

  isUpdated=$(/home/$me/.cargo/bin/rustup check | grep -B 1 "Up to date")
  if [ -z "$isUpdated" ]; then
    echo "🦀 Updating rust..."
    /home/$me/.cargo/bin/rustup update
  else
    echo "🦀 Skip rust update..."
  fi
}

# Download floresta from releases and check integrity
# TODO: add signature verification when possible
download_floresta() {
  echo "🌳 Download floresta $defaultTag..."
  curl -L -o $tarDest --retry 5 --retry-delay 10 "$tarSrc"

  sha256res=$(sha256sum $tarDest | awk -F" " '{ print $1 }')
  sha256exp="733b1e2bcecfdf5ab552b81db428b125e6f8154cccfda69b5e746da7a4a0a322"
  if [ ! "$sha256res" == "$sha256exp" ]; then
    echo "❌ Integrity check failed for $tarDest"
    exit 1
  else
    echo "🌳 Integrity check passed"
  fi
}

# Build floresta from releases and install florestad (daemon)
# and floresta_cli (command line interface) into /usr/local/bin
build_floresta () {
  echo "🌳 Extracting floresta $tarDest to /tmp..."
  tar -xzf $tarDest -C /tmp

  echo "🦀 Building florestad and floresta-cli v$defaultTag..."
  cd $bdlDir
  RUSTFLAGS="-C link-arg=-fuse-ld=mold -C target-cpu=native"
  cargo build --release \
            --bin florestad \
            --bin floresta_cli \
            --features json-rpc \
            --locked

  echo "🌳 Copying binaries to /usr/local/bin (need sudo)..."
  sudo install -m 0755 -t /usr/local/bin/ $bdlDir/target/release/florestad
  sudo install -m 0755 -t /usr/local/bin/ $bdlDir/target/release/floresta_cli
}

# Setup florestad servic.e
# It will prepare the user florestad with systemd-users and folders with systemd-tmpfiles.
# Optionally, it will generate ssl key and certificate when this script receives -s command
# to include --ssl-cert-path, --ssl-key-path and --ssl-eletrum-address 0.0.0.0:50002
setup_service() {
  florestaTmpPath=/usr/lib/tmpfiles.d/florestad.conf
  florestaUserPath=/usr/lib/sysusers.d/florestad.conf
  florestaService=/usr/lib/systemd/system/florestad.service

  # Check for user-sysuser.d
  echo "🐧 Setup floresta sysusers.d..."
  echo "u florestad - - $florestaDir" | sudo tee $florestaUserPath > /dev/null
  echo "🐧 Applying $florestaUserPath (need sudo)"
  sudo systemd-sysusers
  if [ $? -ne 0 ]; then
    echo "❌ Failed to create systemd-sysusers"
    exit 1
  fi

  # Check for tmpfiles.d
  echo "🐧 Setup floresta tmpfiles.d..."
  echo "d $florestaDir 0710 florestad florestad - -" | sudo tee $florestaTmpPath > /dev/null
  echo "d $florestaLib 0710 florestad florestad - -" | sudo tee -a $florestaTmpPath > /dev/null
  echo "🐧 Applying $florestaTmpPath (need sudo)"
  sudo systemd-tmpfiles --create
  if [ $? -ne 0 ]; then
    echo "❌ Failed to create systemd-tmpfiles"
    exit 1
  fi

  # Generate SSL keys and certificates if SSL is enabled
  if [ "$enable_ssl" = true ]; then
    echo "🔐 Generating SSL keys and certificates..."
    ssl_dir="$florestaLib/ssl"
    sudo mkdir -p "$ssl_dir"
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout "$ssl_dir/florestad.key" \
      -out "$ssl_dir/florestad.crt" \
      -subj "/CN=florestad"
    sudo chown -R florestad:florestad "$ssl_dir"
  fi

  # Build config file
  echo "🐧 Generating $florestaLib/config.toml (need sudo)"
  sudo tee $florestaLib/config.toml > /dev/null <<EOF
[wallet]
xpubs = [$([ -n "$wallet_xpub" ] && echo "$wallet_xpub")]
descriptors = [$([ -n "$wallet_descriptor" ] && echo "$wallet_descriptor")]
addresses = []
EOF

  # Build service file
  echo "🐧 Generating $florestaService (need sudo)"
  sudo tee $florestaService > /dev/null <<EOF
[Unit]
Description=Floresta: A Lightweight Utreexo-powered Bitcoin full node implementation
Documentation=https://github.com/vinteumorg/Floresta
After=network-online.target time-set.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/florestad --daemon --network=$network --data-dir=$florestaDir --config-file=$florestaLib/config.toml --pid-file=$florestaRun/florestad.pid --log-to-file $([ "$assume_utreexo" = true ] && echo "--assume-utreexo")$([ "$enable_ssl" = true ] && echo "--ssl-cert-path /etc/florestad/ssl/florestad.crt --ssl-key-path /etc/florestad/ssl/florestad.key --ssl-electrum-address 0.0.0.0:50002")

# Ensure that the service is ready after the MainPID exists
Type=forking
PIDFile=$florestaRun/florestad.pid

# Don't enter a restart loop, as it might corrupt our database
Restart=no

TimeoutStartSec=infinity
TimeoutStopSec=600

# Make sure we can read from the config file
ExecStartPre=/bin/chgrp florestad /etc/florestad
User=florestad
Group=florestad

# /run/florestad
RuntimeDirectory=florestad
RuntimeDirectoryMode=0710

# /etc/florestad
ConfigurationDirectory=florestad
ConfigurationDirectoryMode=0710

# /var/lib/florestad
StateDirectory=florestad
StateDirectoryMode=0710

# Provide a private /tmp and /var/tmp.
PrivateTmp=true

# Mount /usr, /boot/ and /etc read-only for the process.
ProtectSystem=full

# Deny access to /home, /root and /run/user
ProtectHome=true

# Disallow the process and all of its children to gain
# new privileges through execve().
NoNewPrivileges=true

# Use a new /dev namespace only populated with API pseudo devices
# such as /dev/null, /dev/zero and /dev/random.
PrivateDevices=true

# Deny the creation of writable and executable memory mappings.
MemoryDenyWriteExecute=true

# Restrict ABIs to help ensure MemoryDenyWriteExecute is enforced
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
}

# show some useful information before start floresta node
show_done() {
  echo "✔️ DONE"
  echo ""
  echo "Before enable/start, please edit '$florestaService' to your needs. After that, run:"
  echo ""
  echo "    sudo systemctl enable florestad.service # this enable service on boot" 
  echo "    sudo systemctl start florestad.service  # this will start the service now"
  echo "    sudo systemctl status florestad.service # this check if service is running well"
  echo "    floresta_cli getblockchaininfo          # this assures all OK"
  echo ""
}

# MAIN SECTION
# Run all functions on sequence
apt_install gcc build-essential pkg-config libssl-dev mold
install_rustup
setup_service
download_floresta
build_floresta
show_done
