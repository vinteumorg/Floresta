FROM rust:1.66.0@sha256:0067330b7e0eacacc5c32f21b720607c0cd61eda905c8d55e6a745f579ddeee9 as builder

WORKDIR /opt/app

COPY Cargo.* ./
COPY florestad/ florestad/
COPY crates/ crates/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build -p florestad --release --features json-rpc

FROM debian:11.6-slim@sha256:171530d298096f0697da36b3324182e872db77c66452b85783ea893680cc1b62

COPY --from=builder /opt/app/target/release/florestad /usr/local/bin/florestad
RUN chmod +x /usr/local/bin/florestad

EXPOSE 50001

CMD [ "florestad", "run"]
