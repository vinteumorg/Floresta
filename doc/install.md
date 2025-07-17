# Installing Floresta

If prefer skip the [build-unix](./build-unix.md) and [run](./run.md) steps, you can using our [`bash` script to install and configure](../contrib/install.sh).

> **> [!WARNING]
> At the time, this script only works for debian-based systems

## About the script

This script will guide the user about Floresta's installation/configuration or removal it from the system. In the case of install, it will:

* check if you have the dependencies to build Floresta, and if not, download them;
* start the guide to desired Floresta's `systemd` service configuration;
* once configured, download the [latest release](https://github.com/vinteumorg/Floresta/releases/latest), build and install the `florestad` and `floresta-cli` binaries with the `jsonrpc` feature;
* warn to run and check if the service is running.

## Running the script

Use `curl` to download the script and execute it with `bash`:

```bash
curl -LsSf https://raw.githubusercontent.com/vinteumorg/Floresta/refs/heads/master/contrib/install.sh| bash
```

Or you can use `wget`:

```bash
wget -qO- https://raw.githubusercontent.com/vinteumorg/Floresta/refs/heads/master/contrib/install.sh | bash
```

### Check dependencies

When you start the command above you could see something like this:

```bash
$ curl -LsSf https://raw.githubusercontent.com/vinteumorg/Floresta/refs/heads/master/contrib/install.sh | bash
✅ Internet connection is available.
🐧 'dialog' is not installed. Installing...
[sudo] password for user:
```

### Start configuration

After the dependencies pre-installation you will see this prompt:

![install.sh initial message](/doc/install-0.png)

### Configure

Press `Ok` to proceed, either to install or uninstall:

![install or uninstall](/doc/install-1.png)

Then you could choose between some basic options, advanced options and review configuration:

![Main menu](/doc/install-2.png)

Choose a supported network for your node:

![choose network](/doc/install-3.png)

You can also add any master pubkey, descriptors or specific addresses:

![add wallet](/doc/install-4.png)

The script also have advanced setup. They are not required, but some are desirable to have, like SSL (TLS):

![advanced config](/doc/install-5.png)

### Review

Before install, is important to review your configuration:

![review](/doc/install-6.png)

### Running

TODO
