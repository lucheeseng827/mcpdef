# Local from-source distroless build of the `mcpdef` binary (static musl). For CI releases the
# multi-arch image is assembled from prebuilt binaries via Dockerfile.release — this one is for
# `docker build` on a developer machine without the release matrix.
#
#   docker build -t mcpdef:dev .
#   docker run --rm mcpdef:dev version
FROM rust:1-bookworm AS build
RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y --no-install-recommends musl-tools && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
# Build only the OSS engine binary; the ee/ plane is a separate workspace and is not present.
RUN cargo build --release --bin mcpdef --target x86_64-unknown-linux-musl && \
    cp target/x86_64-unknown-linux-musl/release/mcpdef /mcpdef

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.source="https://github.com/lucheeseng827/mcpdef" \
      org.opencontainers.image.description="Fast, self-hostable, single-binary MCP gateway & governance plane" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /mcpdef /usr/local/bin/mcpdef
# /var/lib/mcpdef, for the ledger and the state, belongs to the user the image runs as (65532):
# Docker gives a new named volume mounted on a directory that directory's owner, and one mounted
# where the image has none is root's, which the gateway cannot write to. The image has no shell
# to make it, so it is the base's own empty home of that user, copied.
COPY --from=gcr.io/distroless/static-debian12:nonroot --chown=65532:65532 /home/nonroot /var/lib/mcpdef
EXPOSE 7878
ENTRYPOINT ["/usr/local/bin/mcpdef"]
CMD ["version"]
