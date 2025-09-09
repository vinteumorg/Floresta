# Floresta Docker Setup Guide

You can find a [Dockerfile](../Dockerfile) in the root directory of the project, which you can use to build a
docker image for Floresta. We also keep the docker image [dlsz/floresta](https://hub.docker.com/r/dlsz/floresta)
on Docker Hub, which you can pull and run directly.

If you want to run using compose, you may use a simple `docker-compose.yml` file like this:

```yaml
services:
  floresta:
    image: dlsz/floresta:latest
    container_name: Floresta
    command: florestad -c /data/config.toml --data-dir /data/.floresta
    ports:
      - 50001:50001
      - 8332:8332
    volumes:
      - /path/config/floresta.toml:/data/config.toml
      - /path/utreexo:/data/.floresta
    restart: unless-stopped
```

Here's a breakdown of the configuration:
- For the command, there are a couple of options that are worth noticing:
  - `--data-dir /data/.floresta` specifies `florestad`'s data directory. Here, `florestad` will store its blockchain data, wallet files, and other necessary data.

  - `-c /data/config.toml` specifies the path to the configuration file inside the container. By default, Floresta looks for a configuration file at the datadir if no configuration file is specified.
  You should mount a volume to at each path to persist data outside the container.

  - `-n <network>` specifies the Bitcoin network to connect to (mainnet, testnet, testnet4, signet, regtest). Make sure this matches your configuration file.
- The `ports` section maps the container's ports to your host machine. Adjust these as necessary.
  - `50001` is used for Electrum server connections. It may change depending on the network you are using or your configuration.

  - `8332` is used for RPC connections. Adjust this if you have changed the RPC port in your configuration file.

This setup will run Floresta in a Docker container and expose the RPC and Electrum ports, so you can connect to them. After the container is running, you can connect to it using an Electrum wallet or any other compatible client.

To use the RPC via CLI, you can use a command like this:

```bash
docker exec -it Floresta floresta-cli getblockchaininfo
```

## Monitoring

Floresta also (optionally) provides [Prometheus](https://prometheus.io/) metrics endpoint, which you can enable at compile time. If you want a quick setup with Grafana, we provide a [docker-compose.yml](../docker-compose.yml) for that as well. Just use:

```bash
docker-compose -f docker-compose.yml up -d
```
