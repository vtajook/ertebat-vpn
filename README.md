# EGN VPN (Ertebat Goostar / ارتباط گستر)

Branded Android VPN client **EGN VPN** by Ertebat Goostar (ارتباط گستر).

- Telegram bot: @egnvpnbot
- Channel: https://t.me/ErtebatGvpn

Based on open-source projects; licensed under GPL-3.0.

## Supported protocols

| Protocol | Status | How |
|----------|--------|-----|
| V2Ray / Xray (VLESS, VMess, Trojan, Shadowsocks, …) | ✅ | latest Xray core, patched in CI (`scripts/patch_xray.py`) so TLS is **not** mandatory; plain TCP / WebSocket work |
| WireGuard | ✅ | Xray WireGuard outbound; import `wireguard://` links or `.conf` files (clipboard / file / QR) |
| SSH | ✅ (new, untested on device) | `ssh://user:pass@host:port#name`; login with sshj, traffic carried through a local SOCKS5 proxy (`direct-tcpip`) into the same tunnel. TCP only (SSH cannot carry UDP); the server must allow TCP forwarding |
| OpenVPN | ⏳ not yet | needs a separate native OpenVPN engine, see below |

Import works from clipboard, local file and QR scan. The QR/clipboard importer recognises the protocol
from the link scheme or file content (`vless://`, `vmess://`, `ssh://`, `wireguard://`, WireGuard `.conf`, …)
and picks the matching parser itself.

## Features

- Multiple configs, groups and subscriptions; quick connect / disconnect; TCP ping and real ping.
- Live session card on the main screen: download and upload speed, data used, time connected.
- Secure storage: every config store is encrypted (MMKV) with a random key that is itself encrypted by
  an Android Keystore key; app backup is turned off and the in-app backup/restore entry is hidden,
  because raw storage files cannot be read on another device.

## Building

The APK is built by GitHub Actions (`.github/workflows/build.yml`): it builds the Xray core bridge and
the tun2socks library from the pinned submodules, then the app. Run it from the **Actions** tab, or push
to `main`.

For updates to install over older versions, add these repository secrets so every build is signed with
the same key: `APP_KEYSTORE_BASE64`, `APP_KEYSTORE_PASSWORD`, `APP_KEYSTORE_ALIAS`, `APP_KEY_PASSWORD`.
Without them the workflow produces test APKs signed with the fixed, public test key `V2rayNG/app/egn-test.jks` (they update each other, but anyone could sign an APK with that key, so never ship it to customers).

Publishing a release (run the workflow with `release_tag`, e.g. `v1.0.0`) feeds the in-app update check.

## Notes

- Source layout and package names (`com.v2ray.ang`) are intentionally kept from upstream v2rayNG to keep
  merging new upstream versions simple; the application id is `ir.ertebatgoostar.vpn`.
- SSH host keys are accepted as presented (no pinning).
