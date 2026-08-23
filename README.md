# mtproto-ssh

Local MTProto proxy that tunnels Telegram traffic over an SSH connection to bypass network censorship.

## Architecture

```
Telegram Client → localhost:20443 → mtproto proxy (9seconds/mtg) → SSH tunnel → VPS → Telegram DC
```

A single Go process in a Docker container. No extra dependencies, no frontend.

## Quick start

```bash
# 1. Edit docker-compose.yml with your VPS credentials
# 2. Build and start
docker compose up -d --build

# 3. On first run, copy the output:
#    - SSH public key → add to VPS ~/.ssh/authorized_keys
#    - tg://proxy link → paste in Telegram or connect manually
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_HOST` | yes | — | VPS hostname or IP |
| `SSH_PORT` | no | `22` | SSH port |
| `SSH_USER` | yes | — | SSH username |
| `MTPROTO_LISTEN` | no | `:20443` | Proxy listen address |
| `DOH_IP` | no | `9.9.9.9` | DNS-over-HTTPS server IP |
| `LOG_LEVEL` | no | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `IP_ALLOWLIST` | no | — | Comma-separated CIDRs to bypass SSH tunnel |
| `DATA_DIR` | no | `/data` | Directory for keys and secrets |

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
