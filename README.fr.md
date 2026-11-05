# PocketNVR Bridge

*[English](README.md) · Français*

Accès distant **chiffré** à Frigate pour l'appli **PocketNVR**, même si votre box n'a pas de serveur WireGuard.

- Un seul petit conteneur, à côté de Frigate. Aucun privilège, aucun module noyau.
- **Ne donne accès qu'à Frigate** : un téléphone connecté ne peut joindre rien d'autre sur votre réseau.
- Ouvre tout seul le port sur la box (UPnP) et trouve votre adresse publique.
- Une page web affiche un **QR code** par téléphone : on le scanne dans PocketNVR, c'est terminé.
- Frigate n'est jamais exposé sur Internet, et aucun reverse proxy n'est nécessaire.

```
PocketNVR (iPhone) ──WireGuard, UDP 51820──► box ──► PocketNVR Bridge ──► Frigate (seulement)
```

> Votre box fait déjà serveur WireGuard (Freebox, UniFi, FRITZ!Box, ASUS, OpenWrt...) ? Le Bridge est inutile : dans l'appli, choisissez **Accès VPN → Box ou routeur**.

## Installation

### Docker (TrueNAS, Unraid, Synology, Raspberry Pi, serveur Linux)

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

### Home Assistant (module complémentaire)

**[Ajouter PocketNVR Bridge à mon Home Assistant](https://my.home-assistant.io/redirect/supervisor_addon/?addon=8085ddbc_pocketnvr_bridge&repository_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge)** (Home Assistant OS ou Supervised)

1. Ouvrez le lien ci-dessus (ou **Installer dans Home Assistant** dans l'appli, sous **Accès VPN**), acceptez l'ajout du dépôt, puis **Installer**.
2. Frigate est le module de Home Assistant ? Activez son port 8971 (module Frigate → onglet Configuration → section Réseau) et laissez `frigate_url` vide : le Bridge prend l'adresse de Home Assistant. Frigate tourne ailleurs ? Mettez son adresse dans `frigate_url`, par exemple `https://192.168.1.20:8971`.
3. Démarrez le module, puis **Ouvrir l'interface web**.

Sans le lien : dans la boutique des modules complémentaires, **⋮ → Dépôts**, ajoutez `https://github.com/pocketnvr/bridge`, puis installez **PocketNVR Bridge**. Home Assistant Container ou Core n'a pas de modules complémentaires : utilisez Docker ci-dessus.

### Notifications (blueprint)

PocketNVR n'affiche lui-même les alertes de Frigate que lorsqu'il est ouvert. Appli fermée, c'est Home Assistant qui vous prévient, par son appli : **[Importer le blueprint dans mon Home Assistant](https://my.home-assistant.io/redirect/blueprint_import/?blueprint_url=https%3A%2F%2Fgithub.com%2Fpocketnvr%2Fbridge%2Fblob%2Fmain%2Fblueprints%2Fpocketnvr_frigate_alerts.yaml)** (ou **Ajouter le blueprint à Home Assistant** dans l'appli, sous **Réglages → Notifications**), puis créez une automatisation à partir de lui : téléphones, caméras, objets, zones, et notifications seulement en votre absence ou non. Un appui sur la notification ouvre l'enregistrement dans PocketNVR. Fonctionne avec toute installation de Home Assistant, avec ou sans le Bridge ; Frigate et Home Assistant doivent partager le même serveur MQTT.

## Ajouter un téléphone

1. Ouvrez `http://<ip-du-serveur>:8765` et choisissez un mot de passe d'administration.
2. **Ajouter un téléphone** : un QR code s'affiche.
3. Dans PocketNVR : **Accès VPN → Scanner le QR**. Vous lisez la page sur l'iPhone lui-même ? Utilisez plutôt **Ouvrir dans PocketNVR**.

Le QR contient la clé privée du téléphone. Le Bridge ne la garde pas : le QR disparaît au bout de 15 minutes. Ensuite, **Nouveau QR** génère une nouvelle clé (et l'ancienne cesse de fonctionner).

Téléphone perdu : **Supprimer**. Son accès est coupé immédiatement.

## Réglages

| Variable | Défaut | Rôle |
|---|---|---|
| `FRIGATE_URL` | (obligatoire ; module Home Assistant : module Frigate sur le port 8971) | Adresse de Frigate **avec son IP**, port 8971 : `https://IP:8971`. Si Frigate est sur la même machine, `https://localhost:8971` fonctionne aussi. **Évite le port 5000** : il n'a pas d'authentification, et chaque téléphone ajouté y serait administrateur de Frigate. |
| `PUBLIC_HOST` | détectée | Nom DynDNS (ex. `maison.duckdns.org`) ou IP publique fixe. Conseillé si votre IP change. |
| `WG_PORT` | `51820` | Port UDP sur lequel le Bridge écoute. |
| `PUBLIC_PORT` | = `WG_PORT` | Port UDP vu depuis Internet (si vous redirigez un autre port sur la box). |
| `WEB_PORT` | `8765` | Page d'administration (réseau local). |
| `UPNP` | `true` | Ouvre le port automatiquement sur la box. |
| `CLIENT_NET` | `10.77.0.0/24` | Adresses données aux téléphones dans le tunnel. |
| `ALLOWED_HOSTS` | (vide) | Noms supplémentaires acceptés pour la page d'administration, séparés par des virgules (ex. derrière un reverse proxy). Par défaut, seules les adresses IP et les noms locaux (`nas`, `nas.local`...) sont acceptés. |

La page d'administration (en français, en anglais, en allemand, en espagnol, en italien ou en néerlandais, selon la langue du navigateur) affiche un diagnostic en direct : Frigate joignable, adresse publique, port ouvert ou non, double NAT, dernière connexion de chaque téléphone.

## Ça ne se connecte pas ?

| Situation | Solution |
|---|---|
| Journal : `FRIGATE_URL="..." invalid` | Écrivez l'adresse complète, avec `http://` ou `https://` et le port : `https://192.168.1.20:8971`. |
| Journal : `bind: address already in use` | Un autre programme utilise déjà le port UDP 51820, souvent l'application WireGuard. Mettez `wg_port` (`WG_PORT` avec Docker) à `51821`. Dans Home Assistant, activez « Afficher les options de configuration facultatives inutilisées » pour le voir. |
| « Ouvrir l'interface web » ne charge pas | Vous accédez à Home Assistant par un nom de domaine ou par Nabu Casa, et la page d'administration ne répond que sur le réseau local. À la maison, ouvrez `http://<IP locale de Home Assistant>:8765`. |
| Appli : « first record does not look like a TLS handshake » | Frigate répond en HTTP simple sur le port 8971 (TLS désactivé dans Frigate). Mettez `http://` dans `frigate_url`, redémarrez, puis **Nouveau QR**. Le tunnel chiffre toujours tout. |
| Appli : Frigate ne répond pas, adresse finissant par `:8765` | 8765 est la page d'administration du Bridge. L'adresse de Frigate utilise son propre port, en général 8971. |
| « Ouverture automatique du port impossible » | Activez l'UPnP sur la box, ou redirigez vous-même le port UDP indiqué vers la machine du Bridge. |
| « Double NAT » | Un autre routeur est devant votre box (ou l'inverse). Redirigez le port UDP sur le routeur de tête. |
| « Votre opérateur partage peut-être l'adresse IPv4 » | Votre opérateur partage votre IPv4 avec d'autres abonnés : aucune connexion entrante n'est possible. Demandez une IPv4 complète (souvent gratuit, depuis l'espace abonné), ou utilisez Tailscale avec le mode « Adresse directe » de l'appli. |
| Le téléphone reste « jamais » connecté | Testez en 4G (pas sur le Wi-Fi de la maison) : certaines box ne savent pas se rejoindre elles-mêmes depuis l'intérieur. |
| Ça marchait puis plus rien | Votre adresse publique a changé : mettez un nom DynDNS dans `PUBLIC_HOST`, puis **Nouveau QR**. |

## Sécurité

- WireGuard (Curve25519, ChaCha20-Poly1305). Le Bridge n'écoute dans le tunnel **que** sur le port de Frigate et relaie vers lui, sans aucun routage vers le reste du réseau.
- La page d'administration n'accepte que les clients du réseau local (ou Tailscale) et les adresses IP ou noms locaux, ce qui bloque l'accès depuis Internet et le DNS rebinding. Elle est protégée par mot de passe (bcrypt), avec cookies `SameSite=Strict`, contrôle d'origine et blocage après 5 essais en 10 minutes. La déconnexion invalide toutes les sessions.
- Supprimer un téléphone coupe immédiatement ses connexions en cours. Les adresses libérées ne sont pas réattribuées tout de suite.
- Le lien « Ouvrir dans PocketNVR » transporte la configuration en HTTP sur le réseau local : il est à usage unique et expire en 15 minutes. Sur un Wi-Fi partagé ou douteux, préférez le QR code.
- `state.json` (mode 0600) contient la clé du Bridge et les **clés publiques** des téléphones, jamais leurs clés privées.
- Le Bridge ne contacte que deux services : des serveurs STUN publics (Cloudflare, Google), pour connaître votre adresse publique, et votre box en UPnP. Aucune vidéo ne quitte votre domicile autrement que vers vos téléphones.

## Développement

```bash
go test -race ./...
go build -o pocketnvr-bridge .
```

Image multi-architecture (amd64, arm64) publiée sur `ghcr.io` par `.github/workflows/release.yml` à chaque tag `vX.Y.Z`. Garde `version` de `pocketnvr_bridge/config.yaml` égal au tag.

Au premier clone, lance `go mod tidy` et commite `go.sum` : les builds deviennent reproductibles et vérifiés.

Sous licence MIT (voir `LICENSE`). La licence ne couvre que le code : PocketNVR est une marque, son nom et son logo ne peuvent pas être utilisés pour un autre produit. « WireGuard » est une marque déposée de Jason A. Donenfeld.
