# Stage 1: Build the Go binary
FROM golang:1.25-bookworm AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o analysis-runner main.go

# Stage 2: Download static CLI tool binaries (needs curl/shell, distroless doesn't have these)
FROM debian:bookworm-slim AS tools
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*

RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

RUN curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" \
    && mv cosign-linux-amd64 /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/kubectl

# Stage 3: Final distroless runtime — no shell, no package manager, minimal attack surface
FROM gcr.io/distroless/base-debian12

COPY --from=builder /app/analysis-runner /usr/local/bin/analysis-runner
COPY --from=tools /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=tools /usr/local/bin/cosign /usr/local/bin/cosign
COPY --from=tools /usr/local/bin/kubectl /usr/local/bin/kubectl

EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/analysis-runner"]
