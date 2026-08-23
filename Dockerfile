# Build stage
FROM golang:1.24-alpine AS builder
ENV GOTOOLCHAIN=auto
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod tidy && CGO_ENABLED=0 go build -o mtproto-ssh .

# Runtime stage
FROM alpine:3.21
WORKDIR /app
COPY --from=builder /app/mtproto-ssh .
ENTRYPOINT ["./mtproto-ssh"]
