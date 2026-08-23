# ssh-gate

SOCKS5/MTProto proxy over SSH tunnel with rule-based routing.

## Architecture

```
Client → localhost:1080 → SOCKS5 → SSH tunnel → VPS → Internet
Client → localhost:20443 → MTProto → SSH tunnel → VPS → Telegram DC

Direct route:
Client → localhost:1080 → SOCKS5 → (DIRECT_RULES) → Internet
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
| `PROXY_MODES` | no | `socks5` | Comma-separated: `socks5`, `mtproto` |
| `SOCKS5_LISTEN` | no | `:1080` | SOCKS5 listen address |
| `MTPROTO_LISTEN` | no | `:20443` | MTProto listen address |
| `DIRECT_RULES` | no | — | Comma-separated rules for direct connections (see below) |
| `DIRECT_IP_FAMILY` | no | `both` | Address families for direct: `ipv4`, `ipv6`, `both` |
| `DOH_IP` | no | `9.9.9.9` | DNS-over-HTTPS server IP |
| `LOG_LEVEL` | no | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `DATA_DIR` | no | `/data` | Directory for keys and secrets |

### DIRECT_RULES format

Rules are checked in order. First match wins. Unmatched traffic goes through the SSH tunnel.

- `ip:1.2.3.0/24` — match CIDR
- `re:.*\.ru$` — match domain regex
- `example.com` — match domain (and subdomains)

Example: `DIRECT_RULES="re:\\.ru$,ip:10.0.0.0/8,internal.local"`

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

### Security note: permitopen=

The SSH key currently allows the VPS to dial any destination. If the VPS has access to internal networks (cloud metadata at `169.254.169.254`, internal APIs, or other services on `127.0.0.1`), an attacker who gains access to the proxy could tunnel to those targets.

To limit exposure, add `permitopen=` to the authorized_keys entry:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,permitopen="1.2.3.4:443",permitopen="5.6.7.8:443" ssh-ed25519 AAAA...
```

Each `permitopen="HOST:PORT"` restricts which destinations the SSH client can dial. Use multiple entries for multiple targets. Note that `permitopen=` disables port forwarding for addresses not explicitly listed, which may reduce the proxy's usefulness as a general-purpose gateway.
