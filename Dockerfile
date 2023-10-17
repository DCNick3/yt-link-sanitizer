# syntax = docker/dockerfile:1.2

FROM bash AS get-tini

# Add Tini init-system
ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static /tini
RUN chmod +x /tini


FROM clux/muslrust:stable as build

ENV CARGO_INCREMENTAL=0

WORKDIR /volume
COPY . .

RUN cargo build --locked --profile ship --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/ship/yt-link-sanitizer /volume/yt-link-sanitizer

FROM gcr.io/distroless/static

LABEL org.opencontainers.image.source https://github.com/DCNick3/yt-link-sanitizer
EXPOSE 3000

ENV ENVIRONMENT=prod

COPY --from=get-tini /tini /tini
COPY --from=build /volume/yt-link-sanitizer /yt-link-sanitizer
COPY config.prod.yaml /

ENTRYPOINT ["/tini", "--", "/yt-link-sanitizer"]