FROM golang:1.24-alpine AS build
ARG VERSION=dev
WORKDIR /src
COPY . .
RUN go mod tidy && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/pocketnvr-bridge .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/pocketnvr-bridge /pocketnvr-bridge
ENV DATA_DIR=/data
VOLUME /data
EXPOSE 51820/udp 8765/tcp
HEALTHCHECK --interval=60s --timeout=5s CMD ["/pocketnvr-bridge", "healthcheck"]
ENTRYPOINT ["/pocketnvr-bridge"]
