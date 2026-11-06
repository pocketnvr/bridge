# PocketNVR Bridge

*English · [Français](README.fr.md)*

**Encrypted** remote access to Frigate for the **PocketNVR** app, even if your router has no WireGuard server.

- One small container, next to Frigate. No privileges, no kernel module.
- **Only gives access to Frigate**: a connected phone can't reach anything else on your network.
- Opens the port on your router by itself (UPnP) and finds your public address.
- A web page shows one **QR code** per phone: scan it in PocketNVR and you're done.
- Frigate is never exposed to the Internet, and you don't need a reverse proxy.

```
PocketNVR (iPhone) ──WireGuard, UDP 51820──► router ──► PocketNVR Bridge ──► Frigate (only)
```

> Your router already runs a WireGuard server (UniFi, FRITZ!Box, ASUS, OpenWrt, Freebox...)? You don't need the Bridge: in the app, pick **Encrypted tunnel → Router**.

## Install

### Docker (TrueNAS, Unraid, Synology, Raspberry Pi, Linux server)

```yaml
services:
  pocketnvr-bridge:
    image: ghcr.io/pocketnvr/bridge:latest
    container_name: pocketnvr-bridge
    restart: unless-stopped
    network_mode: host
    environment:
      FRIGATE_URL: https://192.168.1.20:8971
    volumes:
      - ./pocketnvr-data:/data
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
```

```bash
docker compose up -d
docker logs pocketnvr-bridge
```

### Home Assistant (add-on)

**[Add PocketNVR Bridge to my Home Assistant](https://my.home-assistant.io/redirect/supervisor_addon/?addon=8085ddbc_pocketnvr_bridge&repository_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge)** (Home Assistant OS or Supervised)

1. Open the link above (or **Install in Home Assistant** in the app, under **Encrypted tunnel**), accept adding the repository, then **Install**.
2. Frigate is the Home Assistant add-on? Enable its port 8971 (Frigate add-on → Configuration tab → Network section) and leave `frigate_url` empty: the Bridge uses Home Assistant's address. Frigate runs elsewhere? Set `frigate_url` to its address, for example `https://192.168.1.20:8971`.
3. Start the add-on, then **Open web UI**.

Without the link: in the add-on store (called the app store since Home Assistant 2026.2), **⋮ → Repositories**, add `https://github.com/pocketnvr/bridge`, then install **PocketNVR Bridge**. Home Assistant Container or Core has no add-ons: use Docker above.

### Notifications (blueprint)

PocketNVR shows Frigate's alerts itself only while it is open. With the app closed, Home Assistant notifies you through its own app: **[Import the blueprint into my Home Assistant](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge%2Fblob%2Fmain%2Fblueprints%2Fpocketnvr_frigate_alerts.yaml)** (or **Add the blueprint to Home Assistant** in the app, under **Settings → Notifications**), then create an automation from it: phones, cameras, objects, zones, and whether to be notified only while you are away. Tapping a notification opens the recording in PocketNVR. Works with any Home Assistant install, with or without the Bridge; Frigate and Home Assistant need the same MQTT broker.

## Add a phone

1. Open `http://<server-ip>:8765` and choose an admin password.
2. **Add a phone**: a QR code appears.
3. In PocketNVR: **Encrypted tunnel → Scan QR**. Reading the page on the iPhone itself? Use **Open in PocketNVR** instead.

The QR code holds the phone's private key. The Bridge doesn't keep it: the QR code disappears after 15 minutes. After that, **New QR** generates a new key (and the old one stops working).

Lost phone: **Delete**. Its access is cut immediately.

## Settings

| Variable | Default | Purpose |
|---|---|---|
| `FRIGATE_URL` | (required; Home Assistant add-on: Frigate add-on on port 8971) | Frigate's address **with its IP**, port 8971: `IP:8971` (the Bridge finds out whether Frigate answers in HTTP or HTTPS). If Frigate runs on the same machine, `https://localhost:8971` works too. **Avoid port 5000**: it has no authentication, and every phone you add would be a Frigate admin. |
| `PUBLIC_HOST` | detected | Dynamic DNS name (e.g. `home.duckdns.org`) or static public IP. Recommended if your IP changes. |
| `WG_PORT` | `51820`, or the next free port | UDP port the Bridge listens on. Empty: 51820, or the next free one if another program uses it (the Bridge keeps it). |
| `PUBLIC_PORT` | = `WG_PORT` | UDP port seen from the Internet (if you forward a different port on the router). |
| `WEB_PORT` | `8765` | Admin page (local network). |
| `UPNP` | `true` | Opens the port on the router automatically. |
| `CLIENT_NET` | `10.77.0.0/24` | Addresses given to the phones inside the tunnel. |
| `ALLOWED_HOSTS` | (empty) | Extra host names accepted for the admin page, comma-separated (e.g. behind a reverse proxy). By default only IP addresses and local names (`nas`, `nas.local`...) are accepted. |

The admin page (English, French, German, Spanish, Italian or Dutch, following the browser language) shows a live diagnosis: Frigate reachable, public address, port open or not, double NAT, last connection of each phone.

## Can't connect?

| Situation | Fix |
|---|---|
| Log: `WireGuard on UDP port ... address already in use` | `wg_port` is set to a port another program already uses, often the WireGuard add-on. Empty `wg_port`: the Bridge then picks a free port by itself (Docker: remove `WG_PORT`). |
| App: "first record does not look like a TLS handshake" | The phone was set up before Bridge 1.1.1, and Frigate answers in plain HTTP. Use **New QR**, or update PocketNVR. |
| App: Frigate doesn't answer, address ending in `:8765` | 8765 is the Bridge's admin page. Frigate's address uses its own port, usually 8971. |
| "Couldn't open the port automatically" / "No UPnP router answered" | Turn on UPnP on the router, or forward the UDP port shown to the Bridge machine yourself. |
| "Double NAT" | Another router sits in front of yours (or the other way round). Forward the UDP port on the upstream router. |
| "Your ISP may be sharing the IPv4 address" | Your ISP shares your IPv4 with other customers (CGNAT): no incoming connection is possible. Ask for a full IPv4 (often free, from your customer area), or use Tailscale with the app's "Direct address" mode. |
| The phone stays "never" connected | Test on 4G/5G (not on your home Wi-Fi): some routers can't reach themselves from the inside. |
| It worked, then stopped | Your public address changed: put a dynamic DNS name in `PUBLIC_HOST`, then **New QR**. |

## Security

- WireGuard (Curve25519, ChaCha20-Poly1305). Inside the tunnel the Bridge listens **only** on Frigate's port and relays to it, with no routing to the rest of the network.
- The admin page only accepts clients from the local network (or Tailscale) and IP addresses or local names, which blocks access from the Internet and DNS rebinding. It is password-protected (bcrypt), with `SameSite=Strict` cookies, origin checks and a lockout after 5 attempts in 10 minutes. Signing out invalidates every session.
- Deleting a phone cuts its open connections immediately. Freed addresses aren't reassigned right away.
- The "Open in PocketNVR" link carries the configuration over HTTP on the local network: it is single-use and expires in 15 minutes. On a shared or untrusted Wi-Fi, prefer the QR code.
- `state.json` (mode 0600) holds the Bridge's key and the phones' **public keys**, never their private keys.
- The Bridge only contacts two services: public STUN servers (Cloudflare, Google), to learn your public address, and your router over UPnP. No video leaves your home except to your phones.

## Development

```bash
go test -race ./...
go build -o pocketnvr-bridge .
```

Multi-arch image (amd64, arm64) published to `ghcr.io` by `.github/workflows/release.yml` on every `vX.Y.Z` tag. Keep `version` in `pocketnvr_bridge/config.yaml` equal to the tag.

On first clone, run `go mod tidy` and commit `go.sum`: builds become reproducible and verified.

Licensed under the MIT license (see `LICENSE`). The license covers the code only: PocketNVR is a trademark, and its name and logo may not be used for another product. "WireGuard" is a registered trademark of Jason A. Donenfeld.
