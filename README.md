# Ertebat Goostar VPN

Branded Android VPN client for Ertebat Goostar (ارتباط گستر).

- Telegram bot: @egnvpnbot
- Channel: https://t.me/ErtebatGvpn

Based on open-source projects; licensed under GPL-3.0.

## Supported protocols

| Protocol | Status | How |
|----------|--------|-----|
| V2Ray / Xray (VLESS, VMess, Trojan, Shadowsocks, …) | ✅ | Xray core from v2rayNG; plain TCP / WebSocket, TLS is **not** mandatory |
| WireGuard | ✅ | Xray WireGuard outbound; import `wireguard://` links or `.conf` files (clipboard / file / QR) |
| SSH | ✅ (new, untested on device) | `ssh://user:pass@host:port#name`; login with sshj, traffic carried through a local SOCKS5 proxy (`direct-tcpip`) into the same tunnel. TCP only (SSH cannot carry UDP); the server must allow TCP forwarding |
| OpenVPN | ⏳ not yet | needs a separate native OpenVPN engine, see below |

Import works from clipboard, local file and QR scan.

## Building

The APK is built by GitHub Actions (`.github/workflows/build.yml`): it builds the Xray core bridge and
the tun2socks library from the pinned submodules, then the app. Run it from the **Actions** tab, or push
to `main`.

For updates to install over older versions, add these repository secrets so every build is signed with
the same key: `APP_KEYSTORE_BASE64`, `APP_KEYSTORE_PASSWORD`, `APP_KEYSTORE_ALIAS`, `APP_KEY_PASSWORD`.
Without them the workflow produces debug-signed APKs (fine for testing only).

Publishing a release (run the workflow with `release_tag`, e.g. `v1.0.0`) feeds the in-app update check.

## Notes

- Source layout and package names (`com.v2ray.ang`) are intentionally kept from upstream v2rayNG to keep
  merging new upstream versions simple; the application id is `ir.ertebatgoostar.vpn`.
- SSH host keys are accepted as presented (no pinning).
