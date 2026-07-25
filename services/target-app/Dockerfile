# Stage 1: Build
FROM golang:1.25-bookworm AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
ARG VERSION=dev
RUN go build -ldflags "-X main.Version=${VERSION}" -o target-app main.go

# Stage 2: Minimal distroless runtime
FROM gcr.io/distroless/base-debian12
COPY --from=builder /app/target-app /usr/local/bin/target-app
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/target-app"]
