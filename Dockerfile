FROM debian:11.6-slim@sha256:171530d298096f0697da36b3324182e872db77c66452b85783ea893680cc1b62 AS builder

ARG BUILD_FEATURES=""

RUN apt-get update && apt-get install -y \
  build-essential \
  cmake \
  curl \
  git \
  libssl-dev \
  pkg-config

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"
RUN rustup default 1.74.0

WORKDIR /opt/app

COPY Cargo.* ./
COPY florestad/ florestad/
COPY crates/ crates/
COPY fuzz/ fuzz/
COPY metrics/ metrics/
COPY doc/ doc/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    if [ -n "$BUILD_FEATURES" ]; then \
      cargo build --release --features "$BUILD_FEATURES"; \
    else \
      cargo build --release; \
    fi

FROM debian:11.6-slim@sha256:171530d298096f0697da36b3324182e872db77c66452b85783ea893680cc1b62

COPY --from=builder /opt/app/target/release/florestad /usr/local/bin/florestad
COPY --from=builder /opt/app/target/release/floresta-cli /usr/local/bin/floresta-cli
RUN chmod +x /usr/local/bin/florestad

EXPOSE 50001
EXPOSE 8332
EXPOSE 3333

CMD [ "florestad" ]
