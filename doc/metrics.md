# Metrics

This project uses [`Prometheus`](https://prometheus.io/) as a monitoring system. To enable it you must build the project with the `metrics` feature enabled:

```sh
cargo build --release --features metrics
```

The easiest way to visualize those metrics is by using some observability graphic tool like [Grafana](https://grafana.com/). To make it easier, you can also straight away use the `docker-compose.yml` file to spin up an infrastructure that will run the project with Prometheus and Grafana.

To run it, first make sure you have [Docker Compose](https://docs.docker.com/compose/) installed and then:

```sh
docker-compose up -d --build
```

Grafana should now be available to you at http://localhost:3000. To log in, please check the credentials defined in the `docker-compose.yml` file.
