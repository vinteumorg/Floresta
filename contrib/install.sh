#!/usr/bin/env bash

# Some necessary global variables
me=$(whoami)
wallet_xpubs=()
wallet_descriptors=()
wallet_addresses=()
assume_valid=""
assume_utreexo=false
enable_ssl=false
enable_cfilters=false
filters_start_height=""
connect=""
zeromq=""
network="bitcoin"
proxy=""
uninstall_mode=false
interactive_mode=true
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
show_usage() {
  echo "Install or uninstall Florestad and floresta_cli in your system."
  echo ""
  echo "Usage:"
  echo "  install.sh [OPTIONS]..."
  echo ""
  echo "Options:"
  echo "  -h, --help                       Show this message."
  echo "  -x, --xpub <XPUB>                Define an xpub to be loaded onto config.toml."
  echo "  -d, --desc <DESC>                Define a descriptor to be loaded onto config.toml."
  echo "  -a, --address <ADDR>             Define am bitcoin address to be loaded onto config.toml"
  echo "  -n, --network <NETWORK>          Pass --network onto built service with valid networks:"
  echo "                                   bitcoin, signet, testnet, regtest (default: bitcoin)."
  echo "  -t, --tag <TAG>                  Choose another tag (default: 0.7.0)."
  echo "  -p, --proxy <IP:PORT>            Pass --proxy=<IP:PORT> onto built service"
  echo "                                   (default: '')"
  echo "  -C  --connect <IP:PORT>          Pass --connect=<IP:PORT> onto built service"
  echo "                                   (default: '')"
  echo "  -z  --zmq-address <IP:PORT>      Pass --zmq-address onto built service"
  echo "                                   (default: '')"
  echo "  -v  --assume-valid <BLOCK_HASH>  Pass --assume-valid=<BLOCK_HASH> onto built service"
  echo "                                   (default: '')"
  echo "  -f, --filters <HEIGHT>           Pass --cfilters and --filters-start-height=<HEIGHT> onto"
  echo "                                   built service. If the value is negative, it's relative"
  echo "                                   to the current tip; e.g., if the current tip is 1000 and"
  echo "                                   we set this value to -100, we will start downloading"
  echo "                                   from height 900 (default: disabled)."
  echo "  -u, --assume-utreexo             Pass --assume-utreexo onto built service"
  echo "                                   (default: disabled)."
  echo "  -s, --ssl                        Enable SSL in Floresta Electrum server. This will create"
  echo "                                   a key and a certificate files as well will pass the options"
  echo "                                   --ssl-cert-path=<path-to-generated-cert>"
  echo "                                   --ssl-key-path=<path-to-generated-key>"
  echo "                                   --ssl-electrum-address=0.0.0.0:50002 onto built service."
  echo "                                   (default: false)"
  echo "  -U, --uninstall                  Uninstall Florestad and remove its files."
  echo "  -N  --non-interactive            Run this script in a non-interactive mode. Required to"
  echo "                                   use the the options above."
  echo "                                   (default: false)"
  echo ""
}

# func: check_interactive_mode
#
# Check if the interactive mode is set or not.
# if is true, continue. If is false, exit the process.
#
# This function is used during option parsing.
check_interactive_mode() {
  if [ "$interactive_mode" = true ]; then
    echo "❌ Need to set --non-interactive mode first"
    exit 1
  fi
}

# Use getopt for long options
OPTIONS=$(getopt -o x:d:a:n:t:p:C:z:v:f:usUNh --long xpub:,desc:,address:,network:,tag:,proxy:,connect:,zmq-address:,assume-valid:,filters:,assume-utreexo,ssl,uninstall,non-interactive,help -n "$0" -- "$@")
if [ $? -ne 0 ]; then
  show_usage
  exit 1
fi

eval set -- "$OPTIONS"

while true; do
  case "$1" in
  -x | --xpub)
    check_interactive_mode
    wallet_xpubs+=("$2")
    shift 2
    ;;
  -d | --desc)
    check_interactive_mode
    wallet_descriptors+=("$2")
    shift 2
    ;;
  -a | --address)
    check_interactive_mode
    wallet_addresses+=("$2")
    shift 2
    ;;
  -n | --network)
    check_interactive_mode
    network="$2"
    shift 2
    ;;
  -v | --assume-valid)
    check_interactive_mode
    assume_valid="$2"
    shift 2 # Corrected from shift to shift 2
    ;;
  -u | --assume-utreexo)
    check_interactive_mode
    assume_utreexo=true
    shift
    ;;
  -s | --ssl)
    check_interactive_mode
    enable_ssl=true
    shift
    ;;
  -f | --filters)
    check_interactive_mode
    enable_cfilters=true
    filters_start_height="$2"
    shift 2
    ;;
  -t | --tag)
    check_interactive_mode
    defaultTag="$2"
    tarSrc="https://github.com/$defaultRepo/Floresta/archive/refs/tags/$defaultTag.tar.gz"
    bdlDir="/tmp/Floresta-$defaultTag"
    tarDest="$bdlDir.tar.gz"
    shift 2
    ;;
  -p | --proxy)
    check_interactive_mode
    proxy="$2"
    shift 2
    ;;
  -C | --connect)
    check_interactive_mode
    connect="$2"
    shift 2
    ;;
  -z | --zmq-address)
    check_interactive_mode
    zeromq="$2"
    shift 2
    ;;
  -U | --uninstall)
    check_interactive_mode
    uninstall_mode=true
    shift
    ;;
  -N | --non-interactive)
    interactive_mode=false
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
# This function validates the provided network. If an invalid network is provided, this function
# will show an error and abort the execution with exit 1
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
    echo "source /home/$me/.cargo/env" >>/home/$me/.profile
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
build_floresta() {
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
  echo "u florestad - - $florestaDir" | sudo tee $florestaUserPath >/dev/null
  echo "🐧 Applying $florestaUserPath (need sudo)"
  sudo systemd-sysusers
  if [ $? -ne 0 ]; then
    echo "❌ Failed to create systemd-sysusers"
    exit 1
  fi

  # Check for tmpfiles.d
  echo "🐧 Setup floresta tmpfiles.d..."
  echo "d $florestaDir 0710 florestad florestad - -" | sudo tee $florestaTmpPath >/dev/null
  echo "d $florestaLib 0710 florestad florestad - -" | sudo tee -a $florestaTmpPath >/dev/null
  echo "🐧 Applying $florestaTmpPath (need sudo)"
  sudo systemd-tmpfiles --create
  if [ $? -ne 0 ]; then
    echo "❌ Failed to create systemd-tmpfiles"
    exit 1
  fi

  # Generate SSL keys and certificates if SSL is enabled
  if [ "$enable_ssl" = true ]; then

    # Check if 'openssl' command exists
    if ! command -v openssl >/dev/null 2>&1; then
      echo "🐧 'openssl' is not installed. Installing..."
      if ! sudo apt-get install -y openssl; then
        echo "❌ Failed to install 'openssl'. Exiting."
        exit 1
      fi
      # Verify installation was successful
      if ! command -v openssl >/dev/null 2>&1; then
        echo "❌ 'openssl' still not found after installation. Exiting."
        exit 1
      fi
    fi

    ssl_dir="$florestaDir/ssl"
    echo "🔐 Generating SSL folder at $ssl_dir"
    sudo mkdir -p "$ssl_dir"

    # generate PKCS#8 private key
    echo "🔐 Generating SSL keys at $ssl_dir/key.pem"
    openssl genpkey -algorithm RSA \
      -out "$ssl_dir/key.pem" \
      -pkeyopt rsa_keygen_bits:2048

    # generate PKCS#8 certificate
    echo "🔐 Generating SSL certificate at $ssl_dir/cert.pem"
    openssl req -x509 -new \
      -key "$ssl_dir/key.pem" \
      -out "$ssl_dir/cert.pem" \
      -days 365 \
      -subj "/CN=localhost"

    sudo chown -R florestad:florestad "$ssl_dir"
  fi

  # Build config file
  echo "🐧 Generating $florestaLib/config.toml (need sudo)"
  sudo tee "$florestaLib/config.toml" >/dev/null <<EOF
[wallet]
xpubs = [
  $(for xpub in "${wallet_xpubs[@]}"; do echo "  \"$xpub\","; done)
]
descriptors = [
  $(for descriptor in "${wallet_descriptors[@]}"; do echo "  \"$descriptor\","; done)
]
addresses = [
  $(for address in "${wallet_addresses[@]}"; do echo "  \"$address\","; done)
]
EOF

  # Build service file
  echo "🐧 Generating $florestaService (need sudo)"
  sudo tee $florestaService >/dev/null <<EOF
[Unit]
Description=Floresta: A Lightweight Utreexo-powered Bitcoin full node implementation
Documentation=https://github.com/vinteumorg/Floresta
After=network-online.target time-set.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/florestad --daemon --network $network --data-dir $florestaDir --config-file $florestaLib/config.toml --pid-file $florestaRun/florestad.pid --log-to-file$([ -n "$proxy" ] && echo " --proxy $proxy ")$([ -n "$connect" ] && echo " --connect $connect ")$([ -n "$zeromq" ] && echo " --zmq-address $zeromq ")$([ -n "$assume_valid" ] && echo " --assume-valid $assume_valid ")$([ "$assume_utreexo" = true ] && echo " --assume-utreexo ")$([ "$enable_cfilters" = true ] && echo " --cfilters ")$([ -n "$filters_start_height" ] && echo " --filters-start-height \"$filters_start_height\" ")$([ "$enable_ssl" = true ] && echo " --ssl-cert-path /etc/florestad/ssl/cert.pem --ssl-key-path /etc/florestad/ssl/key.pem --ssl-electrum-address 0.0.0.0:50002")

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
cleanup_profile() {
  echo "🐧 Creating a backup of /home/$me/.profile"
  cp ~/.profile ~/.profile.bak

  echo "🧹 Removing cargo reference from /home/$me/.profile"
  if ! sed -i "\|source /home/$me/.cargo/env|d" ~/.profile; then
    echo "❌ Failed to modify /home/$me/.profile. Restoring /home/$me/.profile"
    mv ~/.profile.bak ~/.profile
    exit 1
  fi
}

# func: show_done
#
# Show some useful information after install and before start floresta node
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

install_floresta() {
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
}

# func: uninstall_floresta
#
# This function stop, deactivate and remove any active florestad.service
# and its systemfiles
uninstall_floresta() {
  echo "🐧 Uninstalling $(which florestad) and $(which floresta_cli) for $me"
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

# func: interactive_prepare
#
# The interactive mode depends on 'dialog' package.
# So, if it do not exists on system, install it.
interactive_prepare() {
  # Check internet by pinging Google DNS (timeout: 3 seconds, count: 1 packet)
  if ping -q -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
    echo "✅ Internet connection is available."
  else
    echo "❌ No internet connection detected. Please check your network."
    exit 1 # Exit the script if there's no internet
  fi

  # Check if 'dialog' command exists
  if ! command -v dialog >/dev/null 2>&1; then
    echo "🐧 'dialog' is not installed. Installing..."
    if ! sudo apt-get install -y dialog; then
      echo "❌ Failed to install 'dialog'. Exiting."
      exit 1
    fi
    # Verify installation was successful
    if ! command -v dialog >/dev/null 2>&1; then
      echo "❌ 'dialog' still not found after installation. Exiting."
      exit 1
    fi
  fi
}

# func: interactive_greeting
#
# This function simply show a "Hello" to
# user, say about what this script do, what
# install, what removes from system, etc
interactive_greeting() {
  dialog --title "Floresta-Installer" \
    --msgbox "Welcome to Floresta: a lightweight Bitcoin full node implementation written in Rust and powered by Utreexo, a novel dynamic accumulator designed for the Bitcoin UTXO set.\n\nThis installer will guide you through the various options you can perform on your new node.\n\nIf you have any questions, don't hesitate to contact us via:\n\n * Discord\n (https://discord.gg/p6w6468c);\n\n * Github\n (https://github.com/vinteumorg/Floresta/issues).\n\nIf you want to disclose a security vulnerability, please email:\n\n * Davidson Souza at me AT dlsouza DOT lol;\n\n * using the PGP key 2C8E0F 836FD7D BBBB9E 9B2EF899 64EC3AB 22B2E3 (https://blog.dlsouza.lol/assets/gpg.asc)." \
    30 60
}

# func: interactive_main_menu
#
# Start asking if user wants to install or uninstall.
# Install will through many options and uninstall simply
# remove all things related to florestad
interactive_main_menu() {
  choice=$(dialog --title "Floresta-Installer (Main menu)" \
    --menu "Choose one of the options below" \
    9 45 25 \
    1 "Setup and install" \
    2 "Uninstall" \
    3>&1 1>&2 2>&3)

  case $choice in
  1)
    uninstall_mode=false
    interactive_setup
    ;;
  2) uninstall_mode=true ;;
  *)
    clear
    exit 0
    ;;
  esac
}

# func: interactive_configure
#
# Ask for which network the user want
# to configure the floresta node
interactive_setup() {
  choice=$(dialog --title "Floresta-Installer (Setup)" \
    --menu "Setup" \
    11 45 25 \
    0 "Network" \
    1 "Wallet" \
    2 "Advanced setup" \
    3 "Review" \
    3>&1 1>&2 2>&3)

  case $choice in
  0) interactive_select_network ;;
  1) interactive_wallet ;;
  2) interactive_advanced_setup ;;
  3) interactive_review ;;
  *) interactive_main_menu ;;
  esac
}

# func: interactive_wallet
#
# Add separated menu to setup xpubs
# descriptors and or addresses
interactive_wallet() {
  choice=$(
    dialog --title "Floresta-Installer (Wallet)" \
      --menu "Wallet" \
      10 45 25 \
      0 "Add xpub/ypub/zpub/tpub" \
      1 "Add descriptors" \
      2 "Add addresses" \
      3>&1 1>&2 2>&3
  )

  case $choice in
  0) interactive_ask_for_add_xpubs ;;
  1) interactive_ask_for_add_descriptors ;;
  2) interactive_ask_for_add_addresses ;;
  *) interactive_setup ;;
  esac
}

# func: interactive_advanced_setup
#
# Add separated menu to setup advanced things:
# - proxy
# - connect to a node
# - zmq-address
# - filters
# - assume-valid
# - assume-utreexo
# - ssl
interactive_advanced_setup() {
  choice=$(
    dialog --title "Floresta-Installer (Advanced setup)" \
      --menu "Advanced setup" \
      14 45 25 \
      0 "Proxy" \
      1 "Connect to another node" \
      2 "Connect to a ZeroMQ server" \
      3 "Filters" \
      4 "Assume valid" \
      5 "Assume utreexo" \
      6 "SSL" \
      3>&1 1>&2 2>&3
  )

  case $choice in
  0) interactive_select_proxy ;;
  1) interactive_connect ;;
  2) interactive_zeromq ;;
  3) interactive_filters ;;
  4) interactive_ask_assume_valid ;;
  5) interactive_assume_utreexo ;;
  6) interactive_ssl ;;
  *) interactive_setup ;;
  esac
}

# func: interactive_select_network
#
# Ask for which network the user want
# to configure the floresta node
interactive_select_network() {
  choice=$(dialog --title "Floresta-Installer" \
    --menu "Which network do you want to use?" \
    11 45 25 \
    1 "bitcoin" \
    2 "signet" \
    3 "testnet" \
    4 "regtest" \
    3>&1 1>&2 2>&3)

  case $choice in
  1)
    network="bitcoin"
    interactive_setup
    ;;
  2)
    network="signet"
    interactive_setup
    ;;
  3)
    network="testnet"
    interactive_setup
    ;;
  4)
    network="regtest"
    interactive_setup
    ;;
  *) interactive_main_menu ;;
  esac
}

# func: interactive_select_proxy
#
# This function setup a proxy if user wants add one
interactive_select_proxy() {
  local proxy_regex="^(socks5:\/\/)((([0-9]{1,3}\.){3}[0-9]{1,3})|\[?[a-fA-F0-9:]+\]?):[0-9]{1,5}$"

  while true; do
    # Prompt user for proxy input
    proxy=$(dialog --title "Floresta-Installer (Set Proxy)" \
      --inputbox "Provide a socks5 proxy address that floresta should use to open outgoing connections. This improves your privacy when running your node, but may make things slower. Examples of socks5 proxy are Tor and I2P (socks5:// followed by IPv4:port or [IPv6]:port)." \
      10 60 \
      3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer (Set Proxy)" \
        --msgbox "❌ Proxy input canceled. Returning to setup menu." 8 45
      interactive_advanced_setup
      return 1
    fi

    # Validate proxy format
    if [[ "$proxy" =~ $proxy_regex ]]; then
      dialog --title "Floresta-Installer (Set proxy)" \
        --msgbox "✅ Proxy set successfully: $proxy" 10 60
      interactive_advanced_setup
      return 0
    else
      dialog --title "Invalid Proxy" \
        --msgbox "❌ The proxy address you entered is invalid.\n\nIt should be in the format:\n- socks5://IPv4:port\n- socks5://[IPv6]:port\n\nExample: socks5://192.168.1.1:9050 or socks5://[2001:db8::1]:9050\n\nReturning to setup menu." 12 60
    fi
  done
}

# func: interactive_connect
#
# This function setup a node to connect when daemon starts
interactive_connect() {
  local connect_regex="^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(:([0-9]{1,5}))?$"

  while true; do
    # Prompt user for proxy input
    connect=$(dialog --title "Floresta-Installer (Set a node to connect)" \
      --inputbox "We'll connect ONLY to this node. It should be an ipv4 address in the format <address>[:<port>]." \
      10 60 \
      3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Connect input canceled. Returning to setup menu." 8 45
      interactive_advanced_setup
      return 1
    fi

    # Validate proxy format
    if [[ "$proxy" =~ $proxy_regex ]]; then
      dialog --title "Floresta-Installer" --msgbox "✅ A node to connect to set successfully: $connect" 10 60
      interactive_advanced_setup
      return 0
    else
      dialog --title "Invalid node to connect" --msgbox "❌ The node address you entered is invalid.\n\nIt should be in the format:\n- http://IPv4:port\n- https://IPv6:port\n- socks5://IPv4:port\n- IPv4:port\n- [IPv6]:port\n\nExample: 192.168.1.100:8080 or [2001:db8::1]:9050\n\nReturning to setup menu." 12 60
    fi
  done
}

# func: interactive_zeromq
#
# This function setup an address for the ZeroMQ server to listen to if user wants add one
interactive_zeromq() {
  local zeromq_regex="^((([0-9]{1,3}\.){3}[0-9]{1,3})|\[?[a-fA-F0-9:]+\]?):[0-9]{1,5}$"

  while true; do
    # Prompt user for zeromq input
    zeromq=$(dialog --title "Floresta-Installer (Set zeromq)" \
      --inputbox "ZMQ is a lightweight and efficient message queue system used for Inter Process Communication. Floresta allows you to use this to get notified about new blocks. This option sets the socket that floresta will listen for ZMQ subscribers (IPv4:port or [IPv6]:port)." \
      10 60 \
      3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer (Set zeromq)" --msgbox "❌ ZeroMQ input canceled. Returning to setup menu." 8 45
      interactive_advanced_setup
      return 1
    fi

    # Validate proxy format
    if [[ "$zeromq" =~ $zeromq_regex ]]; then
      dialog --title "Floresta-Installer (Set zeromq)" --msgbox "✅ ZeroMQ set successfully: $zeromq" 10 60
      interactive_advanced_setup
      return 0
    else
      dialog --title "Invalid ZeroMQ" --msgbox "❌ The zeromq address you entered is invalid.\n\nIt should be in the format:\n- IPv4:port\n- [IPv6]:port\nExample: 192.168.1.100:1080 or [2001:db8::1]:1080\n\nReturning to setup menu." 12 60
    fi
  done
}

# func: interactive_filters
#
# Ask if user want to use --cfilters or not
interactive_filters() {
  local filters_start_height_regex="^-?[0-9]+$"

  while true; do
    # Prompt user for filters_start_height input
    filters_start_height=$(dialog --title "Floresta-Installer (Set enable filters)" \
      --inputbox $'Do you want to use \'cfilters\' and \'filters-start-height\'?\n\n"cfilters" let you query for chain data after IBD, like wallet rescan, finding a utxo, finding specific tx_ids. Will cause more disk usage.\n\n"filters-start-height" download block filters starting at this height. Negative numbers are relative to the current tip. For example, if the current tip is at height 1000, and we set this value to -100, we will start downloading filters from height 900.\n' \
      20 60 \
      3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      enable_cfilters=false
      dialog --title "Floresta-Installer (Set enable filters)" --msgbox "❌ Enable filters input canceled. Returning to setup menu." 8 45
      interactive_advanced_setup
      return 1
    fi

    # Validate filters format
    if [[ "$filters_start_height" =~ $filters_start_height_regex ]]; then
      enable_cfilters=true
      dialog --title "Floresta-Installer (Set enable filters)" --msgbox "✅ Enable filters set successfully: $filters_start_height" 10 60
      interactive_advanced_setup
      return 0
    else
      enable_cfilters=false
      dialog --title "Invalid filter start height" --msgbox "❌ The filters start height you entered is invalid.\n\nIt should be in the format:\n- Positive number (1, 2, 3...)\n- Negative number (-1, -2, -3...)\n\nReturning to setup menu." 12 60
    fi
  done
}

# func: interactive_ask_assume_valid
#
# Ask if user wants to use --assume-valid=<BLOCK_HASH> with validation
interactive_ask_assume_valid() {
  if dialog --title "Floresta-Installer" --yesno "Do you want to use 'assume-valid'?\n\nThis option assumes that scripts before this height are valid." 15 60; then
    interactive_assume_valid
    if [ $? -ne 0 ]; then
      assume_valid="" # Clear invalid value
      dialog --title "Floresta-Installer" --msgbox "❌ Invalid BLOCK_HEIGHT detected. Must be a numeric value." 8 45
      return 1 # Restart process
    fi

    # Show confirmation
    dialog --title "Floresta-Installer" --msgbox "Assume-valid block height set to: $assume_valid" 8 45
    interactive_advanced_setup
  else
    assume_valid=""
    interactive_advanced_setup
  fi
}

# func: interactive_assume_valid
#
# Prompt user to enter a valid BLOCK_HEIGHT for --assume-valid
interactive_assume_valid() {
  block_height=$(dialog --title "Floresta-Installer (Assume Valid)" \
    --inputbox "Enter the BLOCK_HEIGHT you want to assume as valid (numeric value):" 10 60 \
    3>&1 1>&2 2>&3)

  # Validate numeric input
  if [[ "$block_height" =~ ^[0-9]+$ ]]; then
    assume_valid="$block_height"
    return 0
  else
    return 1
  fi
}

# func: interactive_assume_utreexo
#
# Ask if user want to use --assume-utreexo or not
interactive_assume_utreexo() {
  if dialog --title "Floresta-Installer" --yesno "Do you want to use 'assume-utreexo'?\n\nThis option will significantly speed up the initial block download, by skipping the validation of the first hundreds of thousands of blocks. However, there's an inherent trust in the developer that the utreexo state is correct. Everything after the assumed height will be fully validated." 15 60; then
    assume_utreexo=true
  else
    assume_utreexo=false
  fi
  interactive_advanced_setup
}

# func: interactive_ssl
#
# Ask if user want to use SSL (Secure Sockets Layer) and if yes,
# add --ssl-electrum-address, --ssl-cert-path and --ssl-key-path to florestad process.
interactive_ssl() {
  if dialog --title "Floresta-Installer" --yesno "Do you want to use SSL (Secure Sockets Layer) for the Electrum Server?\n\nThis is particularly important if you want to access the Electrum Server from a public untrusted network. This will add encryption and authentication to your service." 12 45; then
    enable_ssl=true
  else
    enable_ssl=false
  fi
  interactive_advanced_setup
}

# func: interactive_ask_for_add_xpubs
#
# Ask if user want to add one or more xpubs to our wallet. For each xpub, add it to the wallet_xpubs.
# Keep asking until user do not want to add more xpubs or if an invalid one appears
interactive_ask_for_add_xpubs() {
  if dialog --title "Floresta-Installer (Ask XPUBs)" --yesno "Do you want to add one or more XPUBs to the node's wallet?" 8 45; then
    while true; do
      interactive_add_xpub # Call function to add XPUB
      if [ $? -ne 0 ]; then
        # If an invalid XPUB was entered, restart the process
        wallet_xpubs=() # Clear XPUBs on error
        dialog --title "Floresta-Installer" --msgbox "❌ Invalid XPUB detected. Restarting XPUB entry process." 8 45
        return 1 # Restart XPUB entry process
      fi

      if ! dialog --title "Add Another XPUB?" --yesno "Do you want to add another XPUB?" 8 45; then
        break
      fi
    done
  fi

  # If at least one XPUB was added, show the list
  if [ ${#wallet_xpubs[@]} -gt 0 ]; then
    xpub_list=""
    for i in "${!wallet_xpubs[@]}"; do
      xpub_list+="\n\n${wallet_xpubs[$i]}"
    done

    dialog --title "Floresta-Installer (XPUBs Added)" --msgbox "The following XPUBs have been added:$xpub_list" 12 70
  else
    dialog --title "Floresta-Installer" --msgbox "No XPUBs were added." 8 45
  fi
  interactive_setup
}

# func: interactive_add_xpub
#
# Ask to user add a valid xpub. If a valid one is provided, add to wallet_xpubs array, show the
# xpub to user confirm it and back to interactive_ask_for_add_xpubs function (thourgh returning true).
# If user provided an invalid one, clean the wallet_xpubs list and back to interactive_ask_for_add_xpubs
# to do all again.
interactive_add_xpub() {
  local xpub_regex="^(xpub|ypub|zpub|tpub)[A-Za-z0-9]{107}$" # (X/Y/Z/T)PUBS are 111 chars

  while true; do
    xpub=$(dialog --title "Floresta-Installer (Add XPUB | YPUB | ZPUB | TPUB)" \
      --inputbox "Provide an XPUB, YPUB, ZPUB, or TPUB" \
      10 60 \
      3>&1 1>&2 2>&3)

    # Check if user pressed Cancel/ESC
    if [[ $? -ne 0 ]]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Descriptor input canceled. Returning to menu." 8 45
      return 1
    fi

    # Validate descriptor format
    if [[ "$xpub" =~ $xpub_regex ]]; then
      prefix="${xpub:0:4}"
      wallet_xpubs+=("$xpub")
      dialog --title "Floresta-Installer" --msgbox "✅ ${prefix^^} added successfully:\n\n$xpub" 10 60
      return 0
    else
      prefix="${xpub:0:4}"
      case "$prefix" in
      xpub | ypub | zpub | tpub)
        error_msg="❌ The $prefix you entered is invalid.\n\nIt must:\n- Be exactly 111 characters\n- Use valid Base58 encoding"
        ;;
      *)
        # Invalid prefix
        error_msg="❌ Invalid descriptor type '$prefix'.\n\nMust start with 'xpub', 'ypub', 'zpub', or 'tpub'."
        ;;
      esac
      dialog --title "Invalid Descriptor" --msgbox "$error_msg" 12 60
      wallet_xpubs=()
      continue
    fi
  done
}

# func: interactive_ask_for_add_descriptors
#
# Ask if user wants to add one or more descriptors to the wallet.
# For each descriptor, add it to the wallet_descriptors array.
# Keep asking until the user does not want to add more descriptors or if an invalid one appears.
interactive_ask_for_add_descriptors() {
  if dialog --title "Floresta-Installer (Ask Descriptors)" --yesno \
    "Do you want to add one or more descriptors to the node's wallet?" 8 45; then

    while true; do
      interactive_add_descriptor # Call function to add a descriptor
      if [ $? -ne 0 ]; then
        # If an invalid descriptor was entered, restart the process
        wallet_descriptors=() # Clear descriptors on error
        dialog --title "Floresta-Installer" --msgbox "❌ Invalid descriptor detected. Restarting descriptor entry process." 8 45
        return 1 # Restart descriptor entry process
      fi

      if ! dialog --title "Add Another Descriptor?" --yesno \
        "Do you want to add another descriptor?" 8 45; then
        break
      fi
    done
  fi

  # If at least one descriptor was added, show the list
  if [ ${#wallet_descriptors[@]} -gt 0 ]; then
    descriptor_list=""
    for i in "${!wallet_descriptors[@]}"; do
      descriptor_list+="\n\n${wallet_descriptors[$i]}"
    done

    dialog --title "Floresta-Installer (Descriptors Added)" --msgbox \
      "The following descriptors have been added:$descriptor_list" 15 70
  else
    dialog --title "Floresta-Installer" --msgbox "No descriptors were added." 8 45
  fi
  interactive_setup
}

# func: interactive_add_descriptor
#
# Ask the user to add a valid descriptor. If a valid one is provided, add it to the
# wallet_descriptors array and show a confirmation.
# If the user provides an invalid one, clear the list and restart the process.
interactive_add_descriptor() {
  local temp_file=$(mktemp) # Create a temporary file for storing input
  echo "" >"$temp_file"     # Ensure the file is initialized

  while true; do
    dialog --title "Floresta-Installer (Add Descriptor)" \
      --editbox "$temp_file" 15 80 2>"$temp_file" # Capture user input

    # Capture exit status (Cancel or OK)
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Descriptor input canceled. Returning to menu." 8 45
      rm -f "$temp_file" # Clean up temporary file
      return 1           # Return with failure
    fi

    # Read input from the temp file (avoids truncation)
    descriptor=$(<"$temp_file") # Use `<` to read entire file content

    # Trim leading/trailing whitespace
    descriptor=$(echo "$descriptor" | tr -d '[:space:]')

    # Ensure descriptor is not empty after trimming
    if [[ -z "$descriptor" ]]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Empty descriptor. Please enter a valid one." 8 45
      continue # Ask user for input again
    fi

    wallet_descriptors+=("$descriptor") # Add to array
    dialog --title "Floresta-Installer" --msgbox "✅ Descriptor added successfully:\n\n$descriptor" 30 80
    rm -f "$temp_file" # Clean up temp file
    return 0           # Valid descriptor added successfully
  done
}

# Function: interactive_add_address
# Prompt user to enter a Bitcoin address and validate its format
interactive_add_address() {
  local address_regex = "^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1q[a-z0-9]{38,59}|bc1p[a-z0-9]{56,87})$"

  address=$(dialog --title "Floresta-Installer (Add Address)" \
    --inputbox "Provide a Bitcoin address (1, 3, bc1q, bc1p)" \
    10 60 \
    3>&1 1>&2 2>&3)

  # User pressed ESC or Cancel
  if [[ $? -ne 0 ]]; then
    dialog --title "Floresta-Installer" --msgbox "❌ Address input canceled. Returning to menu." 8 45
    return 1
  fi

  if [[ "$address" =~ $address_regex ]]; then
    wallet_addresses+=("$address")
    dialog --title "Floresta-Installer" --msgbox "✅ Address added successfully:\n\n$address" 10 60
    return 0
  else
    dialog --title "Invalid Address" --msgbox "❌ Invalid Bitcoin address format.\n\nMust start with:\n- '1' for Legacy\n- '3' for P2SH\n- 'bc1q' for Bech32\n- 'bc1p' for Taproot" 12 60
    wallet_addresses=()
    return 1
  fi
}

# Function: interactive_ask_for_add_addresses
# Interactively ask and collect Bitcoin addresses
interactive_ask_for_add_addresses() {
  if dialog --title "Floresta-Installer (Ask Addresses)" --yesno "Do you want to add one or more Bitcoin addresses?" 8 50; then
    while true; do
      interactive_add_address
      if [ $? -ne 0 ]; then
        dialog --title "Floresta-Installer" --msgbox "❌ Invalid address detected. Restarting address entry process." 8 45
        return 1
      fi

      if ! dialog --title "Add Another Address?" --yesno "Do you want to add another address?" 8 45; then
        break
      fi
    done
  fi

  if [ ${#wallet_addresses[@]} -gt 0 ]; then
    address_list=""
    for addr in "${wallet_addresses[@]}"; do
      address_list+="\n$addr"
    done
    dialog --title "Floresta-Installer (Addresses Added)" --msgbox "The following addresses have been added:$address_list" 12 70
  else
    dialog --title "Floresta-Installer" --msgbox "No addresses were added." 8 45
  fi
  interactive_setup
}

interactive_review() {
  # Build review message
  review_message+="Review your choices. Choose 'Yes' to proceed or 'No' to exit this installer.\n\n"
  review_message+="Network:            $network\n"
  review_message+="Proxy:              $([ -n "$proxy" ] && echo "$proxy" || echo "Not configured")\n"
  review_message+="ZeroMQ:             $([ -n "$zeromq" ] && echo "$zeromq" || echo "Not configured")\n"
  review_message+="Connect to:         $([ -n "$connect" ] && echo "$connect" || echo "Not configured")\n"
  review_message+="Filters:            $([ -n "$filters_start_height" ] && echo $filters_start_height || "Not configured")\n"
  review_message+="Assume valid:       $([ -n "$assume_valid" ] && echo "$assume_valid" || echo "Not configured")\n"
  review_message+="Assume utreexo:     $assume_utreexo\n"
  review_message+="Enable SSL:         $enable_ssl\n"

  # Append XPUBs
  review_message+="Wallet XPUBs:"
  if [ ${#wallet_xpubs[@]} -gt 0 ]; then
    for xpub in "${wallet_xpubs[@]}"; do
      review_message+="\n\n$xpub"
    done
  else
    review_message+="       No XPUBs added."
  fi

  review_message+="\n\nWallet descriptors:"
  if [ ${#wallet_descriptors[@]} -gt 0 ]; then
    for descriptor in "${wallet_descriptors[@]}"; do
      review_message+="\n\n$descriptor"
    done
  else
    review_message+=" No descriptors added."
  fi

  review_message+="\n\nWallet addresses:"
  if [ ${#wallet_addresses[@]} -gt 0 ]; then
    for address in "${wallet_addresses[@]}"; do
      review_message+="\n\n$address"
    done
  else
    review_message+=" No addresses added."
  fi

  # Show information in a dialog message box
  dialog --title "Floresta-Installer (Review)" --yesno "$review_message" 20 90

  choice=$?
  if [ $choice = 0 ]; then
    return 0
  else
    interactive_setup
  fi
}

# func: interactive_run
#
# Run all interactive_* functions in a logical sequence
interactive_run() {
  interactive_prepare
  interactive_greeting
  interactive_main_menu

  # If user select uninstall, exit the dialog
  if [ "$uninstall_mode" = true ]; then
    return 0
  fi
}

# MAIN SECTION
if [ "$interactive_mode" = true ]; then
  interactive_run
fi

if [ "$uninstall_mode" = true ]; then
  clear
  uninstall_floresta
else
  clear
  install_floresta
fi
