FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine3.24 AS builder
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/asapot ./cmd/asapot

FROM scratch
COPY --from=builder /out/asapot /asapot
USER 2000:2000
STOPSIGNAL SIGTERM
ENTRYPOINT ["/asapot"]
