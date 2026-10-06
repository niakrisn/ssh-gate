# syntax=docker/dockerfile:1

# Build stage
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ENV GOTOOLCHAIN=auto
ARG TARGETOS
ARG TARGETARCH
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o ssh-gate .

# Runtime stage
FROM alpine:3.22
WORKDIR /app
COPY --from=builder /app/ssh-gate .
RUN addgroup -S sshgate && adduser -S sshgate -G sshgate && \
    chown -R sshgate:sshgate /app && \
    chmod 0755 /app
USER sshgate
ENTRYPOINT ["./ssh-gate"]
