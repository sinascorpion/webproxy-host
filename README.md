# Webproxy Host

[فارسی](README.fa.md)

A small Go control panel for Telegram WEB proxies. Password-only login at a
private URL, a separate public website, multiple domains/Secrets/sponsor tags,
and complete `tg://webproxy` links. No Node.js, database, root access, systemd,
NGINX or Certbot is required by the application.

## Hosting

Use a Linux amd64/arm64 application host that permits proxy workloads. It must
allow a child process, persistent storage, outbound HTTPS/TCP to Telegram,
WebSocket upgrades, streaming requests and long polls. Connect public HTTPS
**443** to the app's assigned HTTP port. Do not cache or challenge proxy traffic.

Import this repository as your source. Choose **Go** and set the start command:

```sh
sh start.sh
```

The launcher downloads a checksum-pinned release binary, avoiding compilation
on a small host. With Go 1.24+ available, you can alternatively build from source:

```sh
go build -trimpath -ldflags='-s -w' -o /tmp/webproxy-host . && /tmp/webproxy-host
```

Set these variables in your host's **Environment** panel:

| Variable | Value |
| --- | --- |
| `ADMIN_PASSWORD` | A long random password, at least 12 characters |
| `PUBLIC_URL` | The exact public HTTPS origin, e.g. `https://your-host.example.com` |
| `DATA_DIR` | Persistent writable folder; default `./data` |
| `ADMIN_UID` | Optional private route, 16–80 letters/digits/`_`/`-`; generated otherwise |

`SERVER_PORT` is read from the host, falling back to `PORT`, then `8080`. The app
listens on `0.0.0.0`. Private loopback core ports default to 18080 and 18082;
set `CORE_PORT`/`CORE_API_PORT` only if needed. The core's first download needs
outbound access to GitHub; no proxy runs before you deploy a profile.

The Console prints your admin URL once at startup. Open it and enter your
password. The route is also retained in `DATA_DIR/admin-path`. Keep it private;
it does not replace authentication.

## Use the panel

1. Add the exact hostname assigned by your host. For another domain, first
   configure its DNS, routing and HTTPS in the host's **Domains** panel.
2. Generate a Secret or paste an existing 32-hex/`dd`-prefixed Secret.
3. Optionally register that Secret with **@MTProxybot** and paste its sponsor tag.
4. Click **Deploy proxy**. After the core is ready, open **Connection links**.

Add more profiles for additional domains or Secrets. A Secret shared across
domains must use the same sponsor tag. Reusing the same hostname and Secret
preserves existing client links. Reconfiguration reconnects active sessions.
**Disable proxy** retains profiles and stays disabled after an app restart.

“Core ready” verifies the local process, not the host's public TLS/WebSocket
path. A compatible Telegram client and working public routing are still needed.
The app does not create DNS records, issue certificates, buy host plans or add
subdomains under a provider-owned hostname. Hostname length alone does not
guarantee SSL coverage. Host-provided aliases/custom domains depend on the host.

## Data and security

Back up `DATA_DIR` before updating. Profiles, Secrets and generated core configs
are private files with mode 0600 in a mode-0700 folder. Keep that folder off your
public repository. Sessions expire after 8 hours; restarting signs everyone out.
Login is rate limited; cookies are HttpOnly/SameSite and Secure on HTTPS. State
changes require a session, matching Origin and CSRF token. The core control API
only listens on loopback. The app uses no third-party fonts, analytics or assets.

Changing `ADMIN_PASSWORD` requires an app restart. A host reverse proxy may hide
client IPs, so login throttling can be shared by visitors behind that proxy.

## Development

```sh
go test ./...
go vet ./...
```

For a local UI preview, set `PUBLIC_URL=http://localhost:8080`, `HOST=127.0.0.1`
and a development-only `ADMIN_PASSWORD`, then `go run .`. Actual proxy execution
requires Linux. Integration tests use an isolated loopback HTTPS server and an
actual Telegram handshake; see the [Actions workflow](.github/workflows/test.yml).

Botkeep integration is **not live-tested**: creation was unavailable when this
project was prepared. Runtime/domain compatibility and provider permission must
be confirmed before deploying there. The project is portable to other app hosts.

[License](LICENSE) · [Dependency notices](NOTICE.md)
