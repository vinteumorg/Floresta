# Proxy Configuration

Floresta will make some connections with random nodes in the P2P network. You may want to use a proxy to hide your IP address. You can do this by
providing a SOCKS5 socket, with the `--proxy` flag. For example, if you’re running Tor on your local machine, you can start `florestad` with the Tor proxy like this:

```bash
# start the daemon with the Tor proxy
florestad --proxy 127.0.0.1:9050
```

This will route all your connections through the Tor network, effectively masking your IP address.
