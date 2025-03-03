#!/usr/bin/env bash

# Some necessary global variables
me=$(whoami)
wallet_xpubs=()
wallet_descriptors=()
assume_utreexo=false
enable_ssl=false
enable_cfilters=false
connect=false
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
  echo "  -t, --tag <TAG>             Choose another tag (default: 0.7.0)."
  echo "  -p, --proxy <IP:PORT>       Pass --proxy=<IP:PORT> onto built service"
  echo "                              (default: '')"
  echo "  -C  --connect <IP:PORT>     Pass --connect=<IP:PORT> onto built service"
  echo "                              (default: '')"
  echo "  -u, --assume-utreexo        Pass --assume-utreexo onto built service"
  echo "                              (default: disabled)."
  echo "  -s, --ssl                   Enable SSL in Floresta Electrum server."
  echo "                              This will create an OpenSSL key and certificate."
  echo "  -c, --cfilters              Pass --cfilters onto built service"
  echo "                              (default: disabled)."
  echo "  -U, --uninstall             Uninstall Florestad and remove its files."
  echo "  -N  --non-interactive       Run this script in a non-interactive mode. Required to use the"
  echo "                              the options above (default: false)"
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
OPTIONS=$(getopt -o x:d:n:t:p:uscUNh --long xpub:,desc:,network:,tag:,proxy:,assume-utreexo,ssl,cfilters,uninstall,non-interactive,help -n "$0" -- "$@")
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
    -n | --network)
      check_interactive_mode
      network="$2"
      shift 2
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
    -c | --cfilters)
      check_interactive_mode
      enable_cfilters=true
      shift
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
  sudo tee "$florestaLib/config.toml" > /dev/null <<EOF
  [wallet]
  xpubs = [
  $(for xpub in "${wallet_xpubs[@]}"; do echo "  \"$xpub\","; done)
  ]
  descriptors = [
  $(for descriptor in "${wallet_descriptors[@]}"; do echo "  \"$descriptor\","; done)
  ]
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
ExecStart=/usr/local/bin/florestad --daemon --network $network --data-dir $florestaDir --config-file $florestaLib/config.toml --pid-file $florestaRun/florestad.pid --log-to-file $( [ -n "$proxy" ] && echo "--proxy $proxy" ) $( [ -n "$connect" ] && echo "--connect $connect" ) $( [ "$assume_utreexo" = true ] && echo "--assume-utreexo" ) $( [ "$enable_cfilters" = true ] && echo "--cfilters" ) $( [ "$enable_ssl" = true ] && echo "--ssl-cert-path /etc/florestad/ssl/florestad.crt --ssl-key-path /etc/florestad/ssl/florestad.key --ssl-electrum-address 0.0.0.0:50002" )

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
    exit 1  # Exit the script if there's no internet
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
         --msgbox "Welcome to Floresta: a lightweight Bitcoin full node implementation written in Rust and powered by Utreexo, a novel dynamic accumulator designed for the Bitcoin UTXO set.\n\nThis installer will guide you through the various options you can perform on your new node.\n\nIf you have any questions, don't hesitate to contact us via:\n\n * Discord\n (https://discord.gg/p6w6468c)\n\n * Github\n (https://github.com/vinteumorg/Floresta/issues)" \
         20 60
}

# func: interactive_main_menu
#
# Start asking if user wanst to install or uninstall.
# Install will through many options and uninstall simply
# remove all things related to florestad
interactive_main_menu() {
  choice=$(dialog --title "Floresta-Installer (Main menu)" \
                  --menu "Choose one of the options below" \
                  10 45 25 \
                  1 "Setup and install" \
                  2 "Uninstall" \
                  3 "Exit" \
                  3>&1 1>&2 2>&3)

  case $choice in
    1)
      uninstall_mode=false
      interactive_setup
      ;;
    2) uninstall_mode=true ;;  
    3)
      clear
      exit 0
      ;;
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
                  18 45 25 \
                  1 "Network" \
                  2 "Proxy" \
                  3 "Connect to another node" \
                  4 "Compact filters" \
                  5 "Assume utreexo" \
                  6 "SSL" \
                  7 "Wallet" \
                  8 "Descriptors" \
                  9 "Review" \
                  10 "Main menu" \
                  3>&1 1>&2 2>&3)

  case $choice in
    1) interactive_select_network ;;
    2) interactive_select_proxy ;;
    3) interactive_connect ;;
    4) interactive_cfilters ;;
    5) interactive_assume_utreexo ;;
    6) interactive_ssl ;;
    7) interactive_ask_for_add_xpubs ;;
    8) interactive_ask_for_add_descriptors ;;
    9) interactive_review ;;
    10) interactive_main_menu ;;
    *)
      clear
      exit 0
      ;;
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
  local proxy_regex="^((http|https|socks5):\/\/)?((([0-9]{1,3}\.){3}[0-9]{1,3})|\[?[a-fA-F0-9:]+\]?):[0-9]{1,5}$"  # Matches optional protocol, IPv4, IPv6, and port

  while true; do
    # Prompt user for proxy input
    proxy=$(dialog --title "Floresta-Installer (Set Proxy)" \
                  --inputbox "Provide a proxy address (Optional: http://, https://, or socks5:// followed by IPv4, IPv6, or domain:port)" \
                  10 60 \
                  3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Proxy input canceled. Returning to setup menu." 8 45
      interactive_setup
      return 1
    fi

    # Validate proxy format
    if [[ "$proxy" =~ $proxy_regex ]]; then
      dialog --title "Floresta-Installer" --msgbox "✅ Proxy set successfully: $proxy" 10 60
      interactive_setup
      return 0
    else
      dialog --title "Invalid Proxy" --msgbox "❌ The proxy address you entered is invalid.\n\nIt should be in the format:\n- http://IPv4:port\n- https://IPv6:port\n- socks5://IPv4:port\n- IPv4:port\n- [IPv6]:port\n\nExample: 192.168.1.100:8080 or [2001:db8::1]:9050\n\nReturning to setup menu." 12 60
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
      interactive_setup
      return 1
    fi

    # Validate proxy format
    if [[ "$proxy" =~ $proxy_regex ]]; then
      dialog --title "Floresta-Installer" --msgbox "✅ A node to connect to set successfully: $proxy" 10 60
      interactive_setup
      return 0
    else
      dialog --title "Invalid node to connect" --msgbox "❌ The node address you entered is invalid.\n\nIt should be in the format:\n- http://IPv4:port\n- https://IPv6:port\n- socks5://IPv4:port\n- IPv4:port\n- [IPv6]:port\n\nExample: 192.168.1.100:8080 or [2001:db8::1]:9050\n\nReturning to setup menu." 12 60
    fi
  done
}

# func: interactive_cfilters
#
# Ask if user want to use --cfilters or not
interactive_cfilters() {
  if dialog --title "Floresta-Installer" --yesno "Do you want to use 'cfilters'?\n\nThose filters let you query for chain data after IBD, like wallet rescan, finding a utxo, finding specific tx_ids. Will cause more disk usage" 15 60; then
    enable_cfilters=true
  else
    enable_cfilters=false
  fi
  interactive_setup
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
  interactive_setup
}

# func: interactive_ssl
# 
# Ask if user want to use SSL (Secure Sockets Layer) and if yes,
# add --ssl-electrum-address, --ssl-cert-path and --ssl-key-path to florestad process.
interactive_ssl() {
  if dialog --title "Floresta-Installer" --yesno "Do you want to use SSL (Secure Sockets Layer)?" 8 45; then
    enable_ssl=true
  else
    enable_ssl=false
  fi
  interactive_setup
}

# func: interactive_ask_for_add_xpubs
#
# Ask if user want to add one or more xpubs to our wallet. For each xpub, add it to the wallet_xpubs.
# Keep asking until user do not want to add more xpubs or if an invalid one appears
interactive_ask_for_add_xpubs() {
  if dialog --title "Floresta-Installer (Ask XPUBs)" --yesno "Do you want to add one or more XPUBs to the node's wallet?" 8 45; then
    while true; do
      interactive_add_xpub  # Call function to add XPUB
      if [ $? -ne 0 ]; then
        # If an invalid XPUB was entered, restart the process
        wallet_xpubs=()  # Clear XPUBs on error
        dialog --title "Floresta-Installer" --msgbox "❌ Invalid XPUB detected. Restarting XPUB entry process." 8 45
        return 1  # Restart XPUB entry process
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
  local xpub_regex="^xpub[A-Za-z0-9]{107}$"  # XPUBs are always 111 characters

  while true; do
    xpub=$(dialog --title "Floresta-Installer (Add XPUB)" \
                  --inputbox "Provide an XPUB" \
                  10 60 \
                  3>&1 1>&2 2>&3)

    # Check if user pressed Cancel or ESC
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer" --msgbox "❌ XPUB input canceled. Returning to menu." 8 45
      return 1  # Return with failure
    fi

    # Validate XPUB format
    if [[ "$xpub" =~ $xpub_regex ]]; then
      wallet_xpubs+=("$xpub")  # Add to array
      dialog --title "Floresta-Installer" --msgbox "✅ XPUB added successfully:\n\n$xpub" 10 60
      return 0  # Valid XPUB added successfully
    else
      dialog --title "Invalid XPUB" --msgbox "❌ The XPUB you entered is invalid.\n\nXPUBs should:\n- Start with 'xpub'\n- Be exactly 111 characters long\n- Follow Base58Check encoding\n\nReturning to menu." 12 60
      wallet_xpubs=()  # Clear all added XPUBs
      return 1  # Return with failure to restart
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
      interactive_add_descriptor  # Call function to add a descriptor
      if [ $? -ne 0 ]; then
        # If an invalid descriptor was entered, restart the process
        wallet_descriptors=()  # Clear descriptors on error
        dialog --title "Floresta-Installer" --msgbox "❌ Invalid descriptor detected. Restarting descriptor entry process." 8 45
        return 1  # Restart descriptor entry process
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
  local temp_file=$(mktemp)  # Create a temporary file for storing input
  echo "" > "$temp_file"  # Ensure the file is initialized

  while true; do
    dialog --title "Floresta-Installer (Add Descriptor)" \
           --editbox "$temp_file" 15 80 2>"$temp_file"  # Capture user input

    # Capture exit status (Cancel or OK)
    if [ $? -ne 0 ]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Descriptor input canceled. Returning to menu." 8 45
      rm -f "$temp_file"  # Clean up temporary file
      return 1  # Return with failure
    fi

    # Read input from the temp file (avoids truncation)
    descriptor=$(<"$temp_file")  # Use `<` to read entire file content

    # Trim leading/trailing whitespace
    descriptor=$(echo "$descriptor" | tr -d '[:space:]')

    # Ensure descriptor is not empty after trimming
    if [[ -z "$descriptor" ]]; then
      dialog --title "Floresta-Installer" --msgbox "❌ Empty descriptor. Please enter a valid one." 8 45
      continue  # Ask user for input again
    fi

    wallet_descriptors+=("$descriptor")  # Add to array
    dialog --title "Floresta-Installer" --msgbox "✅ Descriptor added successfully:\n\n$descriptor" 30 80
    rm -f "$temp_file"  # Clean up temp file
    return 0  # Valid descriptor added successfully
  done
}

interactive_review() {
  # Build review message
  review_message+="Review your choices. Choose 'Yes' to proceed or 'No' to exit this installer.\n\n"
  review_message+="Network:            $network\n"
  review_message+="Proxy:              $proxy\n"
  review_message+="Connect to:         $connect\n"
  review_message+="Compact filters:    $enable_cfilters\n"
  review_message+="Assume Utreexo:     $assume_utreexo\n"
  review_message+="Enable SSL:         $enable_ssl\n"

  # Append XPUBs
  review_message+="Wallet XPUBs:"
  if [ ${#wallet_xpubs[@]} -gt 0 ]; then
    for xpub in "${wallet_xpubs[@]}"; do
      review_message+="\n\n$xpub"
    done
  else
    review_message+="        No XPUBs added."
  fi

  review_message+="\n\nWallet descriptors:"
  if [ ${#wallet_descriptors[@]} -gt 0 ]; then
    for descriptor in "${wallet_descriptors[@]}"; do
      review_message+="\n\n$descriptor"
    done
  else
    review_message+="  No descriptors added."
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
