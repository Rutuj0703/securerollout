#STAGE 1: Building the Go binary
FROM golang:1.23-bookworm AS builder

WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go build -o analysis-runner main.go

#STAGE 2: Final runtime image with trivy, cosign, kubectl installed

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

#Installing Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

#Installing cosign
RUN curl -O -L "https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64" \
    && mv cosign-linux-amd64 /usr/local/bin/cosign \
    && chmod +x /usr/local/bin/cosign

#Installing kubectl
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && rm kubectl

#Copying the compiled Go binary from the builder stage
COPY --from=builder /app/analysis-runner /usr/local/bin/analysis-runner

EXPOSE 8081
ENTRYPOINT ["/usr/local/bin/analysis-runner"]
