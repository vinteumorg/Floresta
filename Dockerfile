FROM debian:11.6-slim@sha256:171530d298096f0697da36b3324182e872db77c66452b85783ea893680cc1b62 AS builder

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
RUN --mount=type=cache,target=/usr/local/cargo/registry \
  cargo build --release

FROM debian:11.6-slim@sha256:171530d298096f0697da36b3324182e872db77c66452b85783ea893680cc1b62

COPY --from=builder /opt/app/target/release/florestad /usr/local/bin/florestad
RUN chmod +x /usr/local/bin/florestad

EXPOSE 50001
EXPOSE 8332

CMD [ "florestad" ]
