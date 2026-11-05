# PocketNVR Bridge

Gives the PocketNVR app encrypted (WireGuard) access to Frigate when you're away from home, without exposing Frigate to the Internet.

Install link (Home Assistant OS or Supervised): [Add PocketNVR Bridge to my Home Assistant](https://my.home-assistant.io/redirect/supervisor_addon/?addon=8085ddbc_pocketnvr_bridge&repository_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge).

## Configuration

| Option | Example | Purpose |
|---|---|---|
| `frigate_url` | `https://192.168.1.20:8971` | **Leave empty with the Frigate add-on**: the Bridge uses Home Assistant's address and port 8971. The Frigate add-on doesn't publish this port by default: first enable 8971 in its Configuration tab (Network section). Frigate elsewhere: its IP address and port 8971. Never port 5000 (no authentication). |
| `public_host` | `home.duckdns.org` | Optional. Dynamic DNS name if your public address changes. |
| `upnp` | `true` | Opens the UDP port on the router automatically. |
| `wg_port` / `public_port` | `51820` | Optional. UDP port used, and port seen from the Internet. |

## Add a phone

1. Start the add-on, then **Open web UI**.
2. Choose an admin password.
3. **Add a phone**: a QR code appears.
4. In PocketNVR: **VPN access → Scan QR**.

The Bridge only gives access to Frigate: the rest of your network can't be reached by the phones.

## Common problems

| Situation | Fix |
|---|---|
| Log: `FRIGATE_URL="..." invalid` | Write the full address, with `http://` or `https://` and the port: `https://192.168.1.20:8971`. |
| Log: `bind: address already in use` | Another program already uses UDP port 51820, often the WireGuard add-on. Set `wg_port` (`WG_PORT` with Docker) to `51821`. In Home Assistant, turn on "Show unused optional configuration options" to see it. |
| "Open web UI" doesn't load | You reach Home Assistant through a domain name or Nabu Casa, and the admin page only answers on the local network. From home, open `http://<Home Assistant's local IP>:8765`. |
| App: "first record does not look like a TLS handshake" | Frigate answers in plain HTTP on port 8971 (TLS turned off in Frigate). Put `http://` in `frigate_url`, restart, then **New QR**. The tunnel still encrypts everything. |
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
| Journal : `FRIGATE_URL="..." invalid` | Écrivez l'adresse complète, avec `http://` ou `https://` et le port : `https://192.168.1.20:8971`. |
| Journal : `bind: address already in use` | Un autre programme utilise déjà le port UDP 51820, souvent l'application WireGuard. Mettez `wg_port` (`WG_PORT` avec Docker) à `51821`. Dans Home Assistant, activez « Afficher les options de configuration facultatives inutilisées » pour le voir. |
| « Ouvrir l'interface web » ne charge pas | Vous accédez à Home Assistant par un nom de domaine ou par Nabu Casa, et la page d'administration ne répond que sur le réseau local. À la maison, ouvrez `http://<IP locale de Home Assistant>:8765`. |
| Appli : « first record does not look like a TLS handshake » | Frigate répond en HTTP simple sur le port 8971 (TLS désactivé dans Frigate). Mettez `http://` dans `frigate_url`, redémarrez, puis **Nouveau QR**. Le tunnel chiffre toujours tout. |
| Appli : Frigate ne répond pas, adresse finissant par `:8765` | 8765 est la page d'administration du Bridge. L'adresse de Frigate utilise son propre port, en général 8971. |

Autres cas : [README](https://github.com/pocketnvr/bridge/blob/main/README.fr.md#ça-ne-se-connecte-pas-).
