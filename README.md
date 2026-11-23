# ssh-gate

SOCKS5 and HTTP CONNECT proxy with direct routing and multiple SSH server pools.

Each new tunnel is assigned to one eligible SSH server using rendezvous hashing over the client IP and destination. The connection stays on one SSH transport until it closes. Each configured server owns an independent pool, health state, client tunnel limit and pending-open limits. Direct routes use the local resolver and remain available when every SSH server is unavailable.

## Start with Docker Compose

```sh
cp config.example.yaml config.yaml
mkdir -p data
```

Edit `config.yaml`: replace the example SSH server and credentials, and remove the HTTP proxy section if it is not needed. Prepare the data directory for the container's fixed uid:

```sh
sudo chown 10001:10001 data
chmod 700 data
```

Start the service and read the generated client public key:

```sh
docker compose up -d --build
docker compose logs
```

Add `data/ssh_key.pub` to the configured account's `authorized_keys`. A restricted entry can use:

```
command="echo 'tunnel only'",no-pty,no-agent-forwarding,no-X11-forwarding,no-user-rc ssh-ed25519 AAAA...
```

Compose publishes proxy ports on all host interfaces by default. Restrict them to trusted networks or change the port bindings to `127.0.0.1`. The Web UI and health endpoints are published on host loopback only.

### Smoke test against the real SSH server

`docker-compose.e2e.yml` runs the current build against the SSH server declared in `.env`, authenticating with the deployment's client key. It publishes 11080 (SOCKS5), 13128 (HTTP) and 19090 (health and UI) on every host interface, so it never overlaps with a normal `docker compose up` and both stacks can run at the same time.

The stand's own gate config lives inline in `docker-compose.e2e.yml` under `configs.gate_config.content`, because only the Compose file can interpolate `${SSH_HOST}`, `${SSH_PORT}`, `${SSH_USER}`, `${DIRECT_RULES}` and `${DIRECT_IP_FAMILY}` from `.env`. Nothing about the server or the routing policy ends up in the repository, and the stand tests the rules the deployment will use. `routing.direct.rules` is written there as one comma-separated string rather than a sequence, because rules contain `[` and `]` and those end a YAML flow sequence, so `[${DIRECT_RULES}]` would not parse. With `DIRECT_RULES` unset, every destination goes through the SSH server. Compose prefers a variable already exported in the shell to the one in `.env`, so when a stand run routes differently from the file, check that shell (`echo "$DIRECT_RULES"`); `.env` itself cannot be sourced, because the patterns contain parentheses. That block is loaded in a test, with the placeholders expanded the way Compose expands them, so a typo fails a test instead of only killing the container at startup. The service is not `read_only` for the same reason: Compose refuses to materialize an inline config into a read-only service, and the deployment keeps `read_only: true`.

Give the stand a storage directory with the client key, so it authenticates as the same account but keeps its own host pins:

```sh
mkdir -p .e2e-data
cp data/ssh_key data/ssh_key.pub .e2e-data/
```

Never point the stand at `./data`. It would rewrite the deployment's `ssh_known_hosts`, which pins the same host under the deployment's own server ID, and a stand is not the place to migrate that file.

```sh
docker compose -f docker-compose.e2e.yml up -d --build
until curl -s http://127.0.0.1:19090/api/status | grep -q '"eligible":true'; do sleep 2; done
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:19090/readyz
curl --noproxy '' -sx http://127.0.0.1:13128 -o /dev/null -w '%{http_code}\n' https://www.cloudflare.com/
curl --noproxy '' -x socks5h://127.0.0.1:11080 -o /dev/null -w '%{http_code}\n' https://www.cloudflare.com/
curl --noproxy '' -sx http://127.0.0.1:13128 -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9090/healthz
docker compose -f docker-compose.e2e.yml logs ssh-gate | grep '"message":"access"' | tail -3
```

Finish with `docker compose -f docker-compose.e2e.yml down`; `.e2e-data` is a plain directory, remove it with `rm -rf` when you want the stand to re-learn the host key.

The wait loop is part of the test, not decoration: a server joins rotation only after two successful HTTPS health checks, roughly 20 seconds, and until then every tunneled hostname fails with `no eligible SSH server`. If it never turns true, read the reason instead of guessing:

```sh
curl -s http://127.0.0.1:19090/api/status | grep -o '"last_error":"[^"]*"'
```

The health check runs over a fresh SSH channel, so it reaches its target from the SSH server's network, not from your machine, and it never falls back to a local address. Two failures mean the target is wrong for that network rather than the code being broken: `tls: failed to verify certificate: certificate signed by unknown authority` means something on that path re-signs TLS (an antivirus or filtering gateway whose root certificate is installed on the client but not on the server), and a bare `EOF` or `SSL_ERROR_SYSCALL` with `bytes_down: 0` means the destination is blocked there. Both leave the server out of rotation by design, so `health.url` has to name a public HTTPS endpoint the SSH server itself reaches cleanly. Check that destination from the same network before blaming the pool.

The first two proxied requests are tunnels. The access log marks them `route=tunnel reason=fallback` with a public `dst`, because the destination name is resolved by tunnel DNS through the SSH server. The third request names `127.0.0.1:9090`, where the proxy dials from inside the container and the health listener keeps its configured port instead of the published one; private, loopback and other non-public addresses never enter the tunnel, so that one is logged `route=direct reason=private`.

`--noproxy ''` is not decoration either: a `no_proxy` that covers loopback (common on a developer machine) makes `curl` ignore `-x` and connect on its own, so the check reports 200 without ever reaching the proxy — possibly a different stack's loopback port. Read the routes back from the log rather than trusting the status code. Note what the flag does and does not do: it clears the bypass list, it does not turn off proxying, so a `*_proxy` environment variable is still honored. Use `--noproxy '*'` when you want to prove a destination is reachable without any proxy in the path.

Because the ports are published on all interfaces, another device on the network can use the proxy with the host address instead of `127.0.0.1`. Those listeners have no authentication, so pin the bindings back to `127.0.0.1:` prefixes in `docker-compose.e2e.yml` on a network you do not control. The Web UI is guarded by a Host allowlist rather than by the bind address, so it answers `403 Host not allowed` to a request whose Host is the host address; add that address to `ui.allowed_hosts` in the inline config to browse the UI from another machine. `/healthz` and `/readyz` accept any Host header and need nothing.

```sh
ipconfig getifaddr en0                                  # the host address
curl --noproxy '' -sx http://<host-address>:13128 -o /dev/null -w '%{http_code}\n' https://www.cloudflare.com/
curl --noproxy '' -s -o /dev/null -w '%{http_code}\n' http://<host-address>:19090/    # 403 until allowlisted
```

The stand declares two SSH transports, so `/api/status` reports per-slot `active_channels` and a burst of concurrent tunnels splits across the slots. The per-server `limits` are sized for live clients: a browser or a phone holds dozens of long-lived connections, `max_pending_opens` has room for destinations that only fail after the server's own connect timeout, and `max_pending_service_opens` carries every tunnel DNS query, so shrinking these caps makes real clients fail fast rather than slow down. When that happens the log says so — `SSH server quota exhausted` with the `limit_type` and the limit reached, and each refused client connection is logged with the same error. Set `ssh.servers: []` in the inline config to check direct-only mode instead: `/readyz` stays 200, the SSH block in the Web UI reports no servers, and every proxied hostname fails with `no eligible SSH server`.

## YAML configuration

The process reads one strict YAML file from `--config`; the default path is `/etc/ssh-gate/config.yaml`. Unknown keys and invalid values stop startup. Change the file and restart the service. The complete nested example is [config.example.yaml](config.example.yaml).

The top-level sections are:

| Section | Purpose |
| --- | --- |
| `proxy.socks5`, `proxy.http` | Each present section enables that proxy and has its own `listen` list |
| `routing.direct` | Ordered direct rules and direct IP family |
| `ssh.keepalive`, `ssh.servers` | Transport keepalive and server pools |
| `balancing` | Hash key, retry budget and passive exclusion |
| `dns.tunnel` | Tunnel DNS servers or one DoH host |
| `health` | Health listener and shared HTTPS probe URL |
| `ui`, `logging`, `storage` | Web UI host allowlist, logs and persistent key directory |

Each `ssh.servers[]` entry has a stable `id`, host, port, username, transport count and limits. Defaults per server are four SSH transports, 4096 client tunnels, 256 pending client opens and 32 pending service opens. The default hash key is `client_ip_destination`; `client_ip` ignores the destination. The destination port and client source port are never part of the hash.

The default retry budget allows three attempts in 30 seconds. Each client SSH channel open and each switch to another SSH server uses one attempt. Passive exclusion defaults to three confirmed transport failures in 30 seconds, followed by 30 seconds excluded. Each server also checks the common `health.url` (default `https://www.youtube.com`) every 10 seconds. TLS certificates are verified, redirects are rejected, three failed checks exclude the server, and two successes admit or restore it. The probe opens a fresh SSH channel and bypasses the DNS cache.

For example, to add another SSH pool, duplicate a server entry and set a new stable `id`. Both servers use the same generated client key. Host key pins are stored by server ID in `ssh_known_hosts`.

### Direct routing and DNS

Direct rules are checked before selecting an SSH pool. Domain rules and `re:` regular expressions use the local resolver. `ip:` CIDR rules can match tunnel DNS answers; if one matches, the direct connection resolves the name locally. Unmatched destinations use the selected server's tunnel DNS. A tunnel DNS failure or NXDOMAIN never falls back to local DNS. Add a direct domain rule for internal names that only the local DNS can resolve.

Private, loopback, link-local, CGNAT and unique-local addresses are not sent through the tunnel. Add a direct rule if the destination should be reached from the local network.

```yaml
routing:
  direct:
    rules:
      - internal.example
      - "ip:10.0.0.0/8"
      - "re:.*\\.lan$"
    ip_family: both
```

`routing.direct.rules` is also accepted as one comma-separated string, which is exactly the value the old `DIRECT_RULES` variable held, so migrating is a paste. Commas delimit entries in that string form only, so a rule containing a comma has to be written as its own sequence entry: splitting `re:host[0,3]$` on commas gives `re:host[0` and `3]$`, two rules that silently match nothing. The string form additionally cannot contain `: ` or ` #`, which YAML reads as structure.

`dns.tunnel.servers` defaults to `1.1.1.1` and `8.8.8.8`, queried over TCP through SSH. Alternatively set `dns.tunnel.doh_host`, for example `dns.google`; the two forms are mutually exclusive. DNS queries never use a local fallback for tunnel routes.

### Migrating from environment variables

Before upgrading, back up the active configuration and data directory, including the old single-line `ssh_known_hosts` fingerprint. Convert the old `SSH_HOST`, `SSH_PORT` and `SSH_USER` values into one `ssh.servers` item with a stable ID, for example `edge-a`. Move keepalive values under `ssh.keepalive` and use the field mapping below for the remaining settings.

The old `MAX_CONNECTIONS` represented an application-wide cap. It is replaced by per-server `ssh.servers[].limits.max_client_tunnels`; the default is 4096 for each server. `PROXY_MODES` is replaced by the presence of `proxy.socks5` and `proxy.http`. `LOCAL_DNS_ON_NXDOMAIN` is removed: direct rules now define which names use local DNS.

| Old environment variable | YAML field or replacement |
| --- | --- |
| `SSH_HOST`, `SSH_PORT`, `SSH_USER` | `ssh.servers[0].host`, `.port`, `.user` |
| `SSH_KEEPALIVE_PERIOD`, `SSH_KEEPALIVE_INTERVAL`, `SSH_KEEPALIVE_PROBES` | `ssh.keepalive.period`, `.interval`, `.probes` |
| `SSH_DIAL_TIMEOUT` | `balancing.retry.timeout` |
| `MAX_CONNECTIONS` | `ssh.servers[].limits.max_client_tunnels` (limit is now per server) |
| `PROXY_MODES` | Remove; presence of `proxy.socks5` and/or `proxy.http` enables each listener set |
| `SOCKS5_LISTEN`, `HTTP_LISTEN` | `proxy.socks5.listen`, `proxy.http.listen` |
| `DIRECT_RULES`, `DIRECT_IP_FAMILY` | `routing.direct.rules` (takes the comma-separated value as written), `routing.direct.ip_family` |
| `TUNNEL_DNS`, `DOH_HOST` | `dns.tunnel.servers`, `dns.tunnel.doh_host` |
| `LOCAL_DNS_ON_NXDOMAIN` | Remove; tunnel DNS never falls back locally |
| `HEALTH_LISTEN`, `UI_ALLOWED_HOSTS` | `health.listen`, `ui.allowed_hosts` |
| `LOG_LEVEL`, `ACCESS_LOG`, `DATA_DIR` | `logging.level`, `logging.access`, `storage.directory` |

The existing client key remains in the same storage directory. Convert the old host fingerprint to a line containing the selected server ID and fingerprint, such as `edge-a SHA256:...`. The new binary rejects a legacy unqualified fingerprint rather than guessing which pool owns it.

To roll back, restore the prior binary/container and its original environment configuration, and restore the backup of `ssh_known_hosts` in the old one-line format. Keep the same `ssh_key` and `ssh_key.pub`; do not generate a new key unless the corresponding authorized key is updated on the SSH server.

## Debian and systemd

The package installs `/etc/ssh-gate/config.yaml` with a loopback SOCKS5 listener and an empty server list, and starts `ssh-gate --config /etc/ssh-gate/config.yaml`. Edit that file to add server entries and restart:

```sh
sudoedit /etc/ssh-gate/config.yaml
sudo systemctl restart ssh-gate
```

The generated key and host pins live under `/var/lib/ssh-gate`. If the old `/etc/default/ssh-gate` contains settings, the package prints a migration notice; it is no longer read. Convert the values before relying on the new configuration.

## Status and Web UI

`/healthz` is a liveness check. `/readyz` reports whether configured proxy listeners are running; it remains ready while SSH pools are down so direct routes continue to work. The process fails startup if a listener cannot bind.

The Web UI is available at `http://127.0.0.1:9090/`. It shows active and completed tunneled connections, their server and transport slot, and tunnel DNS status. Direct connections are not part of the SSH connection history.

Each SSH server is drawn as three quota meters — client tunnels, pending client opens, pending service opens — where the bar and the percent show the share of the limit, because a bare count means nothing without the capacity behind it (99 of 4096 and 99 of 128 are different situations). The service meter also carries `+N`: channels the server holds that no client tunnel owns, which are tunnel DNS queries and the HTTPS probe on the same transport. Under the meters every SSH transport gets one line with its slot, state and connection count.

TCP counters (RTT current and minimum, retransmissions since connect, bytes in both directions) stay collapsed while a transport is calm. They expand by themselves when retransmissions or RTT grow between polls, when the transport reports an error or loses the connection, and on click. Clicking pins the line open until it is clicked again, so a noisy transport can be read without the 2.5 second poll folding it back. Retransmissions are counted since the transport connected, so the useful number is the growth shown in parentheses, not the total.

`GET /api/status` keeps `dns`, `active`, `active_total` and `uptime_s`. Each entry in `dns.servers[]` reports a resolver's state through the SSH server identified by `server_id`. The `ssh` object contains aggregate `connected`, aggregate `eligible`, and `servers[]`. Each server reports its ID, address, state, reason, last HTTPS check, eligibility, active channels, quota usage and transport states. Each transport includes its state, error, open-channel count and TCP statistics when available.

The Web UI and `/api/*` allow only `localhost`, loopback addresses, the health listener's host and names in `ui.allowed_hosts`. `/healthz` and `/readyz` accept any Host header. Keep the UI bound to loopback or an otherwise trusted interface: it has no login.

## Data and network exposure

The persistent data directory contains `ssh_key`, `ssh_key.pub` and `ssh_known_hosts`. Keep it across container recreation and package upgrades. The container runs as uid/gid 10001; prepare a bind-mounted data directory with that ownership.

The proxy listeners have no authentication. Limit network exposure with host firewall rules or bind them to loopback. On the SSH server, use `permitopen=` in `authorized_keys` to restrict which destinations the key can reach when appropriate.
