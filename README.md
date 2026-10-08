# ssh-gate

SOCKS5/HTTP proxy over SSH tunnel with rule-based routing.

## Architecture

```
Client → localhost:1080 → SOCKS5 → SSH tunnel → VPS → Internet
Client → localhost:3128 → HTTP   → SSH tunnel → VPS → Internet

Direct route:
Client → localhost:1080 → SOCKS5 → (DIRECT_RULES) → Internet
Client → localhost:3128 → HTTP   → (DIRECT_RULES) → Internet
```

Single Go process in a Docker container. No extra dependencies.

## Quick start

```bash
# 1. Create .env from the example and fill in your VPS credentials
cp .env.example .env && $EDITOR .env
# 2. Build and start
docker compose up -d --build

# 3. Check first-run output
docker compose logs

# 4. Copy the SSH public key to VPS ~/.ssh/authorized_keys:
#    command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...
```

An SSH connection failure is never fatal: if the VPS is unreachable at
startup, the proxies, health endpoints and Web UI still come up (readyz
reports 503, the UI shows the tunnel as disconnected) and the dialer retries
in the background until the tunnel comes up.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_HOST` | yes | — | VPS hostname or IP |
| `SSH_PORT` | no | `22` | SSH port |
| `SSH_USER` | yes | — | SSH username |
| `SSH_DIAL_TIMEOUT` | no | `30s` | Max duration of a single destination dial through the tunnel (Go duration, must be positive and below 10m — the connection history window). A dial to a blackholed host fails with a deadline error instead of hanging |
| `SSH_KEEPALIVE_PERIOD` | no | `10s` | Tunnel liveness period (Go duration): OS TCP keepalive idle period plus the SSH-layer `keepalive@openssh.com` probe interval that drops a stuck-but-TCP-alive transport (unanswered probe closes the tunnel within ~2 x period; the monitor reconnects). `0` disables both |
| `SSH_KEEPALIVE_INTERVAL` | no | `1s` | Keepalive probe retransmission interval (Go duration, rounded to whole seconds). `0` keeps the kernel default |
| `SSH_KEEPALIVE_PROBES` | no | `5` | Unanswered keepalive probes before the connection is declared dead. `0` keeps the kernel default. Worst-case silent-death detection = `PERIOD + INTERVAL x PROBES` (defaults: 15 s) |
| `PROXY_MODES` | no | `socks5` | Comma-separated: `socks5`, `http` |
| `SOCKS5_LISTEN` | no | `:1080` | SOCKS5 listen address |
| `HTTP_LISTEN` | no | `:3128` | HTTP proxy listen address (CONNECT + absolute-form requests) |
| `DIRECT_RULES` | no | — | Comma-separated rules for direct connections (see below) |
| `DIRECT_IP_FAMILY` | no | `both` | Address families for direct: `ipv4`, `ipv6`, `both` (compose sets `ipv4`) |
| `DOH_HOST` | no | `cloudflare-dns.com` | DNS-over-HTTPS endpoint for tunnel destinations, queried through the SSH tunnel; direct destinations keep local DNS. Definitive DoH answers, including NXDOMAIN, are authoritative; the local resolver is a fallback only while the endpoint is unreachable. An empty value disables DoH; under compose interpolation (`${DOH_HOST:-cloudflare-dns.com}`) an empty value becomes the default, so remove the variable to disable it there |
| `HEALTH_LISTEN` | no | `127.0.0.1:9090` | Health + Web UI listen address (compose sets `0.0.0.0:9090` inside the container and maps it to `127.0.0.1:9090` on the host) |
| `LOG_LEVEL` | no | `info` | Log level (`debug`, `info`, `warn`, `error`) (compose sets `warn`) |
| `DATA_DIR` | no | `/data` | Directory for keys and secrets |

### DIRECT_RULES format

Rules are checked in order. First match wins. Unmatched traffic goes through the SSH tunnel.

- `ip:1.2.3.0/24` — match CIDR
- `re:.*\.ru$` — match domain regex
- `example.com` — match domain (and subdomains); matching is case- and trailing-dot-insensitive

Example: `DIRECT_RULES="re:\.ru$,ip:10.0.0.0/8,internal.local"` (one backslash — a doubled `re:\\.ru$` would match a literal backslash and never fire)

## Web UI

The proxy exposes a Web UI at `http://127.0.0.1:9090/` (same address as the health endpoint, no authentication). It shows:

- **Active** — tunnels currently open: destination `host:port`, protocol, client source, status, start time, duration, bytes up/down
- **History** — finished connections with the close reason (last 1000 connections / 10 minutes, in-memory ring buffer — lost on restart)

Search by IP or hostname and pagination (50 per page, 2.5 s polling) are supported. Connections matching `DIRECT_RULES` (direct route) are not tracked; only traffic tunneled over SSH appears in the UI. The endpoint is intentionally bound to host loopback — do not expose it publicly.

API: `GET /api/connections?tab=active|history&q=<substring>&page=<n>&page_size=<n>`.

## Data volume

The `./data` directory (mounted as `/data`) stores:

- `ssh_key` / `ssh_key.pub` — ed25519 keypair (generated on first run)
- `ssh_known_hosts` — SSH host key fingerprint (saved on first connection)

The container runs as uid/gid `10001`. A bind mount keeps the host directory
ownership (it does not inherit ownership from the image), so prepare the
directory before the first `docker compose up`:

```bash
mkdir -p data && sudo chown 10001:10001 data && chmod 700 data
```

Upgrading from earlier images: `sudo chown -R 10001:10001 data` — key files
are `0600` and unreadable under the old uid; the app would silently generate
a new key and desync the VPS `authorized_keys`.

## SSH authorized_keys

Restrict the key to tunnel-only access:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...
```

### Network exposure

The default `docker-compose.yml` binds the SOCKS5 proxy (1080) and the HTTP proxy (3128) to all host interfaces for LAN access, without authentication. Keep the host in a trusted network; if LAN access is not needed, bind the ports to `127.0.0.1` instead.

### Security note: permitopen=

The SSH key currently allows the VPS to dial any destination. If the VPS has access to internal networks (cloud metadata at `169.254.169.254`, internal APIs, or other services on `127.0.0.1`), an attacker who gains access to the proxy could tunnel to those targets.

To limit exposure, add `permitopen=` to the authorized_keys entry:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,permitopen="1.2.3.4:443",permitopen="5.6.7.8:443" ssh-ed25519 AAAA...
```

Each `permitopen="HOST:PORT"` restricts which destinations the SSH client can dial. Use multiple entries for multiple targets. Note that `permitopen=` disables port forwarding for addresses not explicitly listed, which may reduce the proxy's usefulness as a general-purpose gateway.
