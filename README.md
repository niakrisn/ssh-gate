# ssh-gate

SOCKS5/HTTP/MTProto proxy over SSH tunnel with rule-based routing.

## Architecture

```
Client → localhost:1080 → SOCKS5 → SSH tunnel → VPS → Internet
Client → localhost:3128 → HTTP   → SSH tunnel → VPS → Internet
Client → localhost:20443 → MTProto → SSH tunnel → VPS → Telegram DC

Direct route:
Client → localhost:1080 → SOCKS5 → (DIRECT_RULES) → Internet
Client → localhost:3128 → HTTP   → (DIRECT_RULES) → Internet
```

Single Go process in a Docker container. No extra dependencies.

## Quick start

```bash
# 1. Edit docker-compose.yml with your VPS credentials
# 2. Build and start
docker compose up -d --build

# 3. Check first-run output
docker compose logs

# 4. Copy the SSH public key to VPS ~/.ssh/authorized_keys:
#    command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...

# 5. If MTProto is enabled, paste the `tg://proxy` link into Telegram to activate the proxy,
#    or enter the server (localhost) and secret manually in Settings → Data and Storage → Proxy
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_HOST` | yes | — | VPS hostname or IP |
| `SSH_PORT` | no | `22` | SSH port |
| `SSH_USER` | yes | — | SSH username |
| `SSH_DIAL_TIMEOUT` | no | `30s` | Max duration of a single destination dial through the tunnel (Go duration, must be positive and below 10m — the connection history window). A dial to a blackholed host fails with a deadline error instead of hanging |
| `PROXY_MODES` | no | `socks5` | Comma-separated: `socks5`, `mtproto`, `http` |
| `SOCKS5_LISTEN` | no | `:1080` | SOCKS5 listen address |
| `HTTP_LISTEN` | no | `:3128` | HTTP proxy listen address (CONNECT + absolute-form requests) |
| `MTPROTO_LISTEN` | no | `:20443` | MTProto listen address |
| `DIRECT_RULES` | no | — | Comma-separated rules for direct connections (see below) |
| `DIRECT_IP_FAMILY` | no | `both` | Address families for direct: `ipv4`, `ipv6`, `both` |
| `DOH_HOST` | no | `cloudflare-dns.com` | DNS-over-HTTPS endpoint for tunnel destinations, queried through the SSH tunnel; direct destinations keep local DNS. The MTProto proxy resolves this endpoint's IP through the tunnel too (bootstrap DoH via 1.1.1.1, so local DNS poisoning cannot affect it) and uses it for the hourly DC config fetch; if the endpoint lacks IP SANs or is unreachable it falls back to 1.1.1.1. Empty disables |
| `HEALTH_LISTEN` | no | `127.0.0.1:9090` | Health + Web UI listen address (compose sets `0.0.0.0:9090` inside the container and maps it to `127.0.0.1:9090` on the host) |
| `LOG_LEVEL` | no | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `DATA_DIR` | no | `/data` | Directory for keys and secrets |

### DIRECT_RULES format

Rules are checked in order. First match wins. Unmatched traffic goes through the SSH tunnel.

- `ip:1.2.3.0/24` — match CIDR
- `re:.*\.ru$` — match domain regex
- `example.com` — match domain (and subdomains)

Example: `DIRECT_RULES="re:\\.ru$,ip:10.0.0.0/8,internal.local"`

## Web UI

The proxy exposes a Web UI at `http://127.0.0.1:9090/` (same address as the health endpoint, no authentication). It shows:

- **Active** — tunnels currently open: destination `host:port`, protocol, client source, status, start time, duration, bytes up/down
- **History** — finished connections with the close reason (last 1000 connections / 10 minutes, in-memory ring buffer — lost on restart)

Search by IP or hostname and pagination (50 per page, 2.5 s polling) are supported. Connections matching `DIRECT_RULES` (direct route) are not tracked; only traffic tunneled over SSH appears in the UI. The endpoint is intentionally bound to host loopback — do not expose it publicly.

API: `GET /api/connections?tab=active|history&q=<substring>&page=<n>&page_size=<n>`.

## Data volume

The `./data` directory (mounted as `/data`) stores:

- `ssh_key` / `ssh_key.pub` — ed25519 keypair (generated on first run)
- `mtproto_secret` — FakeTLS secret (generated on first run)
- `ssh_known_hosts` — SSH host key fingerprint (saved on first connection)

## SSH authorized_keys

Restrict the key to tunnel-only access:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...
```

### Network exposure

The default `docker-compose.yml` binds the HTTP proxy (3128) and MTProto (20443) to all host interfaces for LAN access, without authentication. Keep the host in a trusted network; if LAN access is not needed, bind the ports to `127.0.0.1` instead.

### Security note: permitopen=

The SSH key currently allows the VPS to dial any destination. If the VPS has access to internal networks (cloud metadata at `169.254.169.254`, internal APIs, or other services on `127.0.0.1`), an attacker who gains access to the proxy could tunnel to those targets.

To limit exposure, add `permitopen=` to the authorized_keys entry:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,permitopen="1.2.3.4:443",permitopen="5.6.7.8:443" ssh-ed25519 AAAA...
```

Each `permitopen="HOST:PORT"` restricts which destinations the SSH client can dial. Use multiple entries for multiple targets. Note that `permitopen=` disables port forwarding for addresses not explicitly listed, which may reduce the proxy's usefulness as a general-purpose gateway.
