# PocketNVR Bridge

Gives the PocketNVR app encrypted (WireGuard) access to Frigate when you're away from home, without exposing Frigate to the Internet.

Install link (Home Assistant OS or Supervised): [Add PocketNVR Bridge to my Home Assistant](https://my.home-assistant.io/redirect/supervisor_addon/?addon=8085ddbc_pocketnvr_bridge&repository_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge).

## Configuration

| Option | Example | Purpose |
|---|---|---|
| `frigate_url` | `https://192.168.1.20:8971` | **Leave empty with the Frigate add-on**: the Bridge uses Home Assistant's address and port 8971. The Frigate add-on doesn't publish this port by default: first enable 8971 in its Configuration tab (Network section). Frigate elsewhere: its IP address and port 8971. Never port 5000 (no authentication). |
| `public_host` | `home.duckdns.org` | Optional. Dynamic DNS name if your public address changes. |
| `upnp` | `true` | Opens the UDP port on the router automatically. |
| `wg_port` / `public_port` | `51820` | Optional. UDP port used, and port seen from the Internet. Empty: 51820, or the next free port if another WireGuard add-on uses it. |

## Add a phone

1. Start the add-on, then **Open web UI**.
2. Choose an admin password.
3. **Add a phone**: a QR code appears.
4. In PocketNVR: **VPN access → Scan QR**.

The Bridge only gives access to Frigate: the rest of your network can't be reached by the phones.

## Common problems

| Situation | Fix |
|---|---|
| Log: `WireGuard on UDP port ... address already in use` | `wg_port` is set to a port another program already uses, often the WireGuard add-on. Empty `wg_port`: the Bridge then picks a free port by itself (Docker: remove `WG_PORT`). |
| App: "first record does not look like a TLS handshake" | The phone was set up before Bridge 1.1.1, and Frigate answers in plain HTTP. Use **New QR**, or update PocketNVR. |
| App: Frigate doesn't answer, address ending in `:8765` | 8765 is the Bridge's admin page. Frigate's address uses its own port, usually 8971. |

More cases: [README](https://github.com/pocketnvr/bridge#cant-connect).

## En français

Donne à l'appli PocketNVR un accès chiffré (WireGuard) à Frigate hors de chez vous, sans exposer Frigate sur Internet.

Lien d'installation (Home Assistant OS ou Supervised) : [Ajouter PocketNVR Bridge à mon Home Assistant](https://my.home-assistant.io/redirect/supervisor_addon/?addon=8085ddbc_pocketnvr_bridge&repository_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge).

1. Module Frigate : activez son port 8971 (onglet Configuration, section Réseau) et laissez `frigate_url` vide, le Bridge prend l'adresse de Home Assistant. Frigate ailleurs : mettez son IP et le port 8971 dans `frigate_url` (ex. `https://192.168.1.20:8971`), jamais le port 5000 (sans authentification).
2. Démarrez le module, puis **Ouvrir l'interface web** (en français si votre navigateur l'est).
3. Choisissez un mot de passe, puis **Ajouter un téléphone**.
4. Dans PocketNVR : **Accès VPN → Scanner le QR**.

Le Bridge ne donne accès qu'à Frigate : le reste de votre réseau n'est pas joignable par les téléphones.

### Problèmes fréquents

| Situation | Solution |
|---|---|
| Journal : `WireGuard on UDP port ... address already in use` | `wg_port` indique un port déjà utilisé par un autre programme, souvent l'application WireGuard. Videz `wg_port` : le Bridge choisit alors seul un port libre (Docker : retirez `WG_PORT`). |
| Appli : « first record does not look like a TLS handshake » | Le téléphone a été configuré avant le Bridge 1.1.1, et Frigate répond en HTTP simple. Utilisez **Nouveau QR**, ou mettez à jour PocketNVR. |
| Appli : Frigate ne répond pas, adresse finissant par `:8765` | 8765 est la page d'administration du Bridge. L'adresse de Frigate utilise son propre port, en général 8971. |

Autres cas : [README](https://github.com/pocketnvr/bridge/blob/main/README.fr.md#ça-ne-se-connecte-pas-).
