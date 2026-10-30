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

An empty `SSH_HOST` or `SSH_USER` is not fatal either: the service runs with
the proxies off, only the health endpoints and the Web UI come up (readyz
reports 503 `not configured`). Every other startup error (an invalid value, a
busy port, an unreadable key) exits with status 78; the systemd unit does not
restart on it.

### Tunnel state

Under systemd (`Type=notify`) the service reports the tunnel state in the
`Status:` line of `systemctl status ssh-gate`; the same state is `ssh.state`
in `GET /api/status`, the Web UI shows it, and readyz names it in its 503
body:

| State | Status line |
|-------|-------------|
| `not_configured` | `Not configured: set SSH_HOST and SSH_USER in /etc/default/ssh-gate, then restart the service` |
| `connecting` | `Connecting to user@host:22` |
| `key_rejected` | `Key not accepted by user@host:22: add /var/lib/ssh-gate/ssh_key.pub to authorized_keys; retry in 8s (attempt 3)` |
| `unreachable` | `Cannot reach user@host:22: connect: connection refused; retry in 8s (attempt 3)` |
| `host_key_mismatch` | `Host key of user@host:22 changed (expected SHA256:..., got SHA256:...): delete /var/lib/ssh-gate/ssh_known_hosts to trust the new key` |
| `ssh_error` | `SSH error: <error>; retry in 8s (attempt 3)` |
| `connected` | `Connected to user@host:22` |
| `reconnecting` | `Tunnel to user@host:22 lost, reconnecting` |

The service reports ready once its listeners are open, without waiting for
the tunnel, so `systemctl start` does not block on the VPS. On shutdown the
line is `Stopping, draining connections`.

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SSH_HOST` | yes | — | VPS hostname or IPv4 address. The tunnel connects over IPv4 only: an IPv6 address is rejected at startup, a hostname needs an A record. Empty: the service runs not configured (see [Tunnel state](#tunnel-state)) |
| `SSH_PORT` | no | `22` | SSH port |
| `SSH_USER` | yes | — | SSH username |
| `SSH_DIAL_TIMEOUT` | no | `30s` | Max duration of a single destination dial through the tunnel (Go duration, must be positive and below 10m — the connection history window). A dial to a blackholed host fails with a deadline error instead of hanging |
| `SSH_KEEPALIVE_PERIOD` | no | `10s` | Tunnel liveness period (Go duration): OS TCP keepalive idle period plus the SSH-layer `keepalive@openssh.com` probe interval that drops a stuck-but-TCP-alive transport (unanswered probe closes the tunnel within ~2 x period; the monitor reconnects). `0` disables both |
| `SSH_KEEPALIVE_INTERVAL` | no | `1s` | Keepalive probe retransmission interval (Go duration, rounded to whole seconds). `0` keeps the kernel default |
| `SSH_KEEPALIVE_PROBES` | no | `5` | Unanswered keepalive probes before the connection is declared dead. `0` keeps the kernel default. Worst-case silent-death detection = `PERIOD + INTERVAL x PROBES` (defaults: 15 s) |
| `PROXY_MODES` | no | `socks5` | Comma-separated: `socks5`, `http` |
| `SOCKS5_LISTEN` | no | `:1080` | SOCKS5 listen address(es), comma-separated for several |
| `HTTP_LISTEN` | no | `:3128` | HTTP proxy listen address(es) (CONNECT + absolute-form requests), comma-separated for several |
| `DIRECT_RULES` | no | — | Comma-separated rules for direct connections (see below) |
| `DIRECT_IP_FAMILY` | no | `both` | Address families for direct: `ipv4`, `ipv6`, `both` (compose sets `ipv4`) |
| `TUNNEL_DNS` | no | `1.1.1.1,8.8.8.8` | DNS servers for tunnel destinations: comma-separated IPs with an optional port, queried over TCP through the SSH tunnel (see [DNS](#dns)) |
| `DOH_HOST` | no | — | DNS-over-HTTPS endpoint to use instead of `TUNNEL_DNS`, also through the SSH tunnel. Hostname only, port 443 only. Setting both variables is a startup error |
| `LOCAL_DNS_ON_NXDOMAIN` | no | `off` | Ask the local resolver when a tunnel resolver says a name does not exist (`on`, `off`, see [DNS](#dns)) |
| `HEALTH_LISTEN` | no | `127.0.0.1:9090` | Health + Web UI listen address (compose sets `0.0.0.0:9090` inside the container and maps it to `127.0.0.1:9090` on the host) |
| `UI_ALLOWED_HOSTS` | no | — | Comma-separated hostnames or IPs (no port) the Web UI and API answer to, in addition to `localhost`, `127.0.0.1`, `::1` and the `HEALTH_LISTEN` host. Needed only to open the UI under a LAN name or address (see [Web UI](#web-ui)) |
| `MAX_CONNECTIONS` | no | `4096` | Limit of concurrent client connections over all proxy listeners; a connection over the limit is closed at once. `0` disables the limit |
| `LOG_LEVEL` | no | `info` | Service log level (`debug`, `info`, `warn`, `error`) (compose sets `warn`) |
| `ACCESS_LOG` | no | `on` | Access log, one line per proxied connection (`on`, `off`). Not affected by `LOG_LEVEL`. `result` is `ok`, `resolve_error`, `dial_error` or `relay_error`; the error text is a warning in the service log with the same `conn_id`. Under systemd it goes to the journal as `ssh-gate-access` (`journalctl -u ssh-gate -t ssh-gate-access`); elsewhere it shares stderr with the service log |
| `DATA_DIR` | no | `/data` | Directory for keys and secrets |

### DIRECT_RULES format

Domain and regex rules are checked first, in order, then `ip:` rules. So a name that matches a domain or regex rule never reaches a tunnel resolver, whatever the order of the rules. Unmatched traffic goes through the SSH tunnel.

- `ip:1.2.3.0/24` — match CIDR. A hostname is resolved the same way as a tunnel destination, so deciding a route never shows a name to the local resolver. An intranet name unknown to public DNS needs a domain rule or `LOCAL_DNS_ON_NXDOMAIN=on`
- `re:.*\.ru$` — match domain regex
- `example.com` — match domain (and subdomains); matching is case- and trailing-dot-insensitive

Example: `DIRECT_RULES="re:\.ru$,ip:10.0.0.0/8,internal.local"` (one backslash — a doubled `re:\\.ru$` would match a literal backslash and never fire)

Private addresses: an IP literal in a private, loopback, link-local, CGNAT (`100.64.0.0/10`) or unique local (`fc00::/7`) range is always dialed directly, without any rule. A hostname routed through the tunnel whose addresses are all in these ranges is refused: through the tunnel the VPS would dial its own network (its localhost, the cloud metadata service). Add a direct rule to reach such a name from the local network. The one exception is a local resolver answer with `LOCAL_DNS_ON_NXDOMAIN=on`, see [DNS](#dns).

### DNS

There are two resolvers. The local one is the resolver of this machine. The tunnel one is either the servers of `TUNNEL_DNS` or the endpoint of `DOH_HOST`, reached through the SSH tunnel, so the local network neither sees these queries nor can forge the answers. `127.0.0.53` in `TUNNEL_DNS` is the resolver of the VPS itself when it runs systemd-resolved.

| Name | Resolver | Route |
|------|----------|-------|
| Matches a domain or `re:` rule | local only | direct |
| Tunnel answer falls in an `ip:` rule | tunnel, then local for the dial | direct |
| Anything else | tunnel | tunnel |
| No tunnel resolver answers | local | tunnel, not cached |
| Tunnel says the name does not exist, setting `off` | tunnel | error |
| Tunnel says the name does not exist, setting `on` | tunnel, then local | tunnel |
| Local answer with only private addresses, setting `on`, name not found by the tunnel or tunnel down | local | direct, `reason=local-private` |
| Local answer with only private addresses, setting `on`, tunnel up but no tunnel resolver answers | local | refused: it may be a block page of the provider |

A tunnel resolver no channel can be opened to is skipped for 10 s, then one lookup tries it again; if all of them are skipped, names go to the local resolver at once. So a blocked port 53 on the VPS costs one 3 s wait per 10 s and not one per connection, but while it lasts the local network sees the names. The Web UI shows it. If the hosting provider blocks port 53, use `DOH_HOST` or `TUNNEL_DNS=127.0.0.53`.

A failure on an open channel, SERVFAIL or silence, is about the one name: the next server is tried and, if none answers, only this name goes to the local resolver. So a web page cannot switch the tunnel resolvers off by asking for a broken domain. The cost: a server that accepts connections and never answers costs up to 3 s per lookup.

`LOCAL_DNS_ON_NXDOMAIN=on` is for names only the local network knows, for example behind a VPN that overrides DNS, when the subnets are not known in advance. The cost:

- Every name public DNS does not know reaches the local resolver, typos included. A provider that answers unknown names with its own page gets that page opened through the tunnel.
- `local-private` connections go direct to private, CGNAT and unique local addresses, also while the tunnel is down. With the VPS down, a name your provider points at a private block page goes there in the clear. Loopback, `0.0.0.0/8` and link-local stay refused. A web page can still use DNS rebinding to reach a service in the local network without authentication: its authoritative server only has to answer the tunnel resolver with NXDOMAIN and the local one with a private address.

Limits:

- A name with a public record gets the tunnel answer, and the local resolver is not asked. An intranet name like that needs a domain rule.
- In Docker the `bridge` network may not see the DNS a VPN set up on the host.
- `TUNNEL_DNS` queries leave the VPS in clear text. `DOH_HOST` encrypts this part of the way too.
- `SSH_HOST` is resolved by the local resolver before any tunnel exists, so a forged answer can stop the tunnel from coming up. Use an IP address where DNS is not trusted.

## Web UI

The proxy exposes a Web UI at `http://127.0.0.1:9090/` (same address as the health endpoint, no authentication). It shows:

- **Active** — tunnels currently open: destination `host:port`, protocol, client source, status, start time, duration, bytes up/down
- **History** — finished connections with the close reason (last 1000 connections / 10 minutes, in-memory ring buffer — lost on restart)
- **DNS** — the tunnel resolvers: last latency, failed lookups out of all lookups, and how many lookups, not connections (SOCKS5 makes two per connection), went to the local resolver because no tunnel resolver answered, for example `DNS: 1.1.1.1 · 14 мс · ошибок 3 из 1200 · 8.8.8.8 не использовался · локальный резерв: 3`. The dot is yellow while a resolver is paused or when a name reached the local resolver in the last minute. Hover the text for the last error

Search by IP or hostname and pagination (50 per page, 2.5 s polling) are supported. Connections on the direct route (`DIRECT_RULES`, `local-private`) are not tracked; only traffic tunneled over SSH appears in the UI. The endpoint is intentionally bound to host loopback — do not expose it publicly.

The same data is the `dns` field of `GET /api/status`, `null` while the proxies are off:

```json
{"mode": "servers", "degraded": false, "local_fallbacks": 3, "last_fallback_at": 1790000000,
 "servers": [{"name": "1.1.1.1", "ok": 1197, "fail": 3, "rtt_ms": 14, "last_ok_at": 1790000000, "last_failed": false, "paused": false, "error": ""}]}
```

`mode` is `servers` or `doh`. Counters run from the process start. `ok` counts answers, NXDOMAIN too; `fail` counts timeouts, refused connections and server errors, with or without a pause. One lookup is one event, a cache hit or a skipped resolver is none. While the tunnel is down, failures are not put on the resolvers: `local_fallbacks` grows alone. `readyz` does not depend on DNS.

The UI and `/api/*` answer only to a `Host` header of `localhost`, `127.0.0.1`, `::1`, the `HEALTH_LISTEN` host or a name in `UI_ALLOWED_HOSTS`, and return 403 otherwise. This stops a web page open in a local browser from reading the connection history through DNS rebinding. `/healthz` and `/readyz` answer to any `Host`.

API: `GET /api/connections?tab=active|history&q=<substring>&page=<n>&page_size=<n>`.

## Data volume

The `./data` directory (mounted as `/data`) stores:

- `ssh_key` / `ssh_key.pub` — ed25519 keypair (generated on first run)
- `ssh_known_hosts` — SSH host key fingerprint, saved on the first connection (trust on first use). Every later connection, including reconnects, must present the same key; a different key fails until the file is deleted

The container runs as uid/gid `10001`. A bind mount keeps the host directory
ownership (it does not inherit ownership from the image), so prepare the
directory before the first `docker compose up`:

```bash
mkdir -p data && sudo chown 10001:10001 data && chmod 700 data
```

Upgrading from earlier images: `sudo chown -R 10001:10001 data` — key files
are `0600` and unreadable under the old uid; the app then refuses to start
with a "read SSH key" error (it does not generate a new key, which would
desync the VPS `authorized_keys`).

## SSH authorized_keys

Restrict the key to tunnel-only access:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...
```

### Network exposure

The default `docker-compose.yml` binds the SOCKS5 proxy (1080) and the HTTP proxy (3128) to all host interfaces for LAN access, without authentication. Keep the host in a trusted network; if LAN access is not needed, bind the ports to `127.0.0.1` instead.

Timeouts and limits: a SOCKS5 client must finish its handshake within 30 s; a plain HTTP request (absolute-form) is closed after 5 minutes without data in either direction; CONNECT tunnels and SOCKS5 relays have no idle limit. `MAX_CONNECTIONS` caps concurrent client connections.

### Security note: permitopen=

ssh-gate refuses tunnel destinations whose addresses are private or loopback (see [DIRECT_RULES format](#direct_rules-format)), but the SSH key itself still allows the VPS to dial any destination. If the VPS has access to internal networks (cloud metadata at `169.254.169.254`, internal APIs, or other services on `127.0.0.1`), an attacker who gains access to the proxy could tunnel to those targets.

To limit exposure, add `permitopen=` to the authorized_keys entry:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc,permitopen="1.2.3.4:443",permitopen="5.6.7.8:443" ssh-ed25519 AAAA...
```

Each `permitopen="HOST:PORT"` restricts which destinations the SSH client can dial. Use multiple entries for multiple targets. Note that `permitopen=` disables port forwarding for addresses not explicitly listed, which may reduce the proxy's usefulness as a general-purpose gateway.
