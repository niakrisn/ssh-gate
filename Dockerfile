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
# Fixed uid/gid: bind-mounted ./data keeps host ownership, so the README
# documents 10001 as the directory owner the app runs as. /data baked into
# the image (mode 0700) so named volumes inherit a writable owner.
RUN addgroup -S -g 10001 sshgate && adduser -S -u 10001 -G sshgate sshgate && \
    mkdir -p /data && chown sshgate:sshgate /data && chmod 0700 /data && \
    chown -R sshgate:sshgate /app && chmod 0755 /app
USER sshgate
ENTRYPOINT ["./ssh-gate"]
