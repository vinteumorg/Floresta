#!/usr/bin/env bash

# Some necessary global variables
me=$(whoami)
wallet_xpub=""
wallet_descriptor=""
assume_utreexo=false
enable_ssl=false
network="bitcoin"
uninstall_mode=false
defaultRepo="vinteumorg"
defaultTag="0.7.0"
tarSrc="https://github.com/$defaultRepo/Floresta/archive/refs/tags/$defaultTag.tar.gz"
bdlDir="/tmp/Floresta-$defaultTag"
tarDest="$bdlDir.tar.gz"
florestaDir="/var/lib/florestad"
florestaLib="/etc/florestad"
florestaRun="/run/florestad"
florestaTmpPath="/usr/lib/tmpfiles.d/florestad.conf"
florestaUserPath="/usr/lib/sysusers.d/florestad.conf"
florestaService="/usr/lib/systemd/system/florestad.service"
distribution=$(lsb_release -sc)
architecture=$(dpkg --print-architecture)

# use stable rust toolchain
export RUSTUP_TOOLCHAIN=stable
export CARGO_TARGET_DIR=$bdlDir/target

# func: show_usage
#
# Function to be printed on console when user need some
# assistance on usage, cli options, etc. 
show_usage () {
  echo "Install or uninstall Florestad and floresta_cli in your system."
  echo ""
  echo "Usage:"
  echo "  install.sh [OPTIONS]..."
  echo ""
  echo "Options:"
  echo "  -h, --help                  Show this message."
  echo "  -x, --xpub <XPUB>           Define an xpub to be loaded onto config.toml."
  echo "  -d, --desc <DESC>           Define a descriptor to be loaded onto config.toml."
  echo "  -n, --network <NETWORK>     Pass --network onto built service with valid networks:"
  echo "                              bitcoin, signet, testnet, regtest (default: bitcoin)."
  echo "  -u, --assume-utreexo        Pass --assume-utreexo onto built service"
  echo "                              (default: disabled)."
  echo "  -s, --ssl                   Enable SSL in Floresta Electrum server."
  echo "                              This will create an OpenSSL key and certificate."
  echo "  -t, --tag <TAG>             Choose another tag (default: 0.7.0)."
  echo "  -U, --uninstall             Uninstall Florestad and remove its files."
  echo ""
}

# Use getopt for long options
OPTIONS=$(getopt -o x:d:n:t:Uush --long xpub:,desc:,network:,tag:,assume-utreexo,ssl,uninstall,help -n "$0" -- "$@")
if [ $? -ne 0 ]; then
  show_usage
  exit 1
fi

eval set -- "$OPTIONS"

while true; do
  case "$1" in
    -x | --xpub)
      wallet_xpub="$2"
      shift 2
      ;;
    -d | --desc)
      wallet_descriptor="$2"
      shift 2
      ;;
    -n | --network)
      network="$2"
      shift 2
      ;;
    -u | --assume-utreexo)
      assume_utreexo=true
      shift
      ;;
    -s | --ssl)
      enable_ssl=true
      shift
      ;;
    -t | --tag)
      defaultTag="$2"
      shift 2
      # Update dependent variables dynamically
      tarSrc="https://github.com/$defaultRepo/Floresta/archive/refs/tags/$defaultTag.tar.gz"
      bdlDir="/tmp/Floresta-$defaultTag"
      tarDest="$bdlDir.tar.gz"
      ;;
    -U | --uninstall)
      uninstall_mode=true
      shift
      ;;
    -h | --help)
      show_usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Invalid option: $1" >&2
      show_usage
      exit 1
      ;;
  esac
done

# func: validate_network
#
# this function validate the suposed network that florestad will run.
# If any of the valid networks are used, this function will call
# `exit 1` and this will stop the current process.
# 
# Valid networks are:
#   - bitcoin
#   - signet
#   - testnet
#   - regtest
validate_network() {
  valid_networks=("bitcoin" "signet" "testnet" "regtest")
  if [[ ! " ${valid_networks[@]} " =~ " ${network} " ]]; then
    echo "❌ Invalid network '$network'. Valid options are: ${valid_networks[*]}"
    exit 1
  fi
}

# func: apt_install
#
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

# func: install_rustup
#
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

# func: download_floresta
#
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

# func: build_floresta
#
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

# func: setup_service
#
# Setup florestad.service
# 
# It will prepare the user florestad with systemd-users and folders with systemd-tmpfiles.
# Optionally, it will generate ssl key and certificate when this script receives -s command
# to include --ssl-cert-path, --ssl-key-path and --ssl-eletrum-address 0.0.0.0:50002
setup_service() {
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
ExecStart=/usr/local/bin/florestad --daemon --network=$network --data-dir=$florestaDir --config-file=$florestaLib/config.toml --pid-file=$florestaRun/florestad.pid --log-to-file $([ "$assume_utreexo" = true ] && echo "--assume-utreexo ")$([ "$enable_ssl" = true ] && echo "--ssl-cert-path /etc/florestad/ssl/florestad.crt --ssl-key-path /etc/florestad/ssl/florestad.key --ssl-electrum-address 0.0.0.0:50002")

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
  echo "✅ $florestaService generated!"
}

# func: Apt cleanup
# check if the specified packages exist and
# then clean all of them from the system
cleanup_apt() {
  local packages=("$@")
  local pkg_manager

  # Package removal only if packages are specified
  if [ ${#packages[@]} -gt 0 ] && [ "$pkg_manager" != "unknown" ]; then
    local to_remove=()

    # Check installed packages
    for pkg in "${packages[@]}"; do
      if dpkg -l | grep -q "^ii  $pkg "; then
        to_remove+=("$pkg")
      fi
    done

    # Remove packages if any
    if [ ${#to_remove[@]} -gt 0 ]; then
      echo "🧹 Removing packages: ${to_remove[*]}"
      sudo apt-get remove -y --purge "${to_remove[@]}"
      sudo apt-get autoremove -y
      sudo apt-get clean -y
    fi
  fi
  echo "✅ Aptget cleanup complete!"
}

# Rust cleanup
# Remove toolchai and directories built within
# $HOME/.cargo/bin/rustup
cleanup_rust() {
  echo "🧹 Cleaning up Rust toolchain"
  if command -v rustup >/dev/null 2>&1; then
    echo 'y' | rustup self uninstall
  elif [ -f "$HOME/.cargo/bin/rustup" ]; then
    echo 'y' | "$HOME/.cargo/bin/rustup" self uninstall
  fi

  # Remove cargo/rust directories
  local rust_dirs=(
    "$HOME/.cargo"
    "$HOME/.rustup"
    "$HOME/.cache/cargo"
    "$HOME/.config/cargo"
  )

  for dir in "${rust_dirs[@]}"; do
    if [ -d "$dir" ]; then
      echo "🧹 Removing $dir"
      rm -rf "$dir"
    fi
  done

  echo "✅ Rust cleanup complete!"
}

# func: cleanup_profile
#
# When we uninstall rustup, we uninstall rust and cargo,
# but to not clean the `source /home/$me/.cargo/env` reference
# on ~/.profile, leading to useless call (and an annoying warning during login).
#
# This function clean this call, making a backup of it if anything goes wrong.
cleanup_profile () {
  echo "🐧 Creating a backup of /home/$me/.profile"
  cp ~/.profile ~/.profile.bak

  echo "🧹 Removing cargo reference from /home/$me/.profile"
  if ! sed -i "\|source /home/$me/.cargo/env|d" ~/.profile; then
    echo "❌ Failed to modify /home/$me/.profile. Restoring /home/$me/.profile"
    mv ~/.profile.bak ~/.profile
    exit 1
  fi
}

# func: uninstall_floresta
#
# This function stop, deactivate and remove any active florestad.service
# and its systemfiles
uninstall_floresta() {
  # Stop the service if running
  if systemctl is-active --quiet florestad; then
    echo "🐧 Stopping Florestad service..."
    sudo systemctl stop florestad
  fi

  # Disable the service
  if systemctl is-enabled --quiet florestad; then
    echo "🐧 Disabling Florestad service..."
    sudo systemctl disable florestad
  fi

  # Remove systemd service file
  if [ -f "$florestaService" ]; then
    echo "🧹 Removing systemd service file: $florestaService"
    sudo rm -f "$florestaService"
  fi

  # Remove systemd configurations
  if [ -f "$florestaTmpPath" ]; then
    echo "🧹 Removing tmpfiles config: $florestaTmpPath"
    sudo rm -f "$florestaTmpPath"
  fi

  if [ -f "$florestaUserPath" ]; then
    echo "🧹 Removing sysusers config: $florestaUserPath"
    sudo rm -f "$florestaUserPath"
  fi

  # Remove application directories
  if [ -d "$florestaDir" ]; then
    echo "🧹 Removing directory: $florestaDir"
    sudo rm -rf "$florestaDir"
  fi

  if [ -d "$florestaLib" ]; then
    echo "🧹 Removing directory: $florestaLib"
    sudo rm -rf "$florestaLib"
  fi

  echo "🧹 Removing /usr/local/bin/florestad"
  sudo rm /usr/local/bin/florestad

  echo "🧹 Removing /usr/local/bin/floresta_cli"
  sudo rm /usr/local/bin/floresta_cli

  # Reload systemd daemon
  echo "🐧 Reloading systemd daemon..."
  sudo systemctl daemon-reload

  echo "✅ Florestad has been successfully uninstalled."
  exit 0
}


# show some useful information before start floresta node
show_done() {
  echo "✅ DONE"
  echo ""
  echo "⚠️ Before enable/start, please edit '$florestaService' to your needs. After that, run:"
  echo ""
  echo "    sudo systemctl start florestad.service  # this will start the service now"
  echo "    sudo systemctl status florestad.service # this check if service is running well"
  echo "    sudo systemctl enable florestad.service # this enable service on boot" 
  echo "    floresta_cli getblockchaininfo          # this assures all OK"
  echo ""
}

# MAIN SECTION
# Run all functions on sequence
# If the user selects uninstall mode, execute the uninstall function
if [ "$uninstall_mode" = true ]; then
  echo "🐧 Uninstalling $(which florestad) and $(which floresta_cli) for $me"
  uninstall_floresta
else
  echo "🐧 Installing $tarSrc for $me"
  validate_network
  apt_install gcc build-essential pkg-config libssl-dev mold
  install_rustup
  setup_service
  download_floresta
  build_floresta
  cleanup_apt gcc build-essential pkg-config libssl-dev mold
  cleanup_rust
  cleanup_profile
  show_done
fi
