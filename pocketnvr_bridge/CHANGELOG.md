# Changelog

## 1.1.2

- The admin page opens inside Home Assistant (Open web UI, or PocketNVR in the sidebar), from anywhere, even through a domain name or Nabu Casa.
- `frigate_url` accepts an address without `http://` or `https://`, and without a port (8971).
- The Bridge finds out whether Frigate answers in HTTP or HTTPS and gives phones the right address.
- UDP port 51820 already taken (by the WireGuard add-on, for example): the Bridge uses the next free port and keeps it. A warning lists the phones set up with a former port.

## 1.1.0

- `frigate_url` can stay empty when Frigate is the Home Assistant add-on: the Bridge then uses Home Assistant's address and Frigate's port 8971 (enable this port in the Frigate add-on).
- One-link install with My Home Assistant (README and the PocketNVR app).

## 1.0.0

- First version.
