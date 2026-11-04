#!/usr/bin/env python3
"""Patch a copy of Xray-core so that plaintext VLESS/Trojan (no TLS/REALITY/encryption) is allowed.

Since Xray 26.7.11 the config builder refuses such outbounds unless the server address is a private
IP or domain (infra/conf/xray.go: requiresTransportSecurity / validateOutboundTransportSecurity).
EGN VPN's own servers use plain VLESS/VMess over TCP and WebSocket, so the check is switched off here
while the core itself stays on the latest version.

Usage: patch_xray.py <path to xray-core source copy>
The build fails loudly when the expected code is not found, so an upstream change is never silently
shipped unpatched.
"""
import pathlib
import sys

MARKER = "func requiresTransportSecurity(address *Address) bool {"
PATCH_TAG = "EGN patch"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    path = pathlib.Path(sys.argv[1]) / "infra" / "conf" / "xray.go"
    if not path.is_file():
        print(f"patch failed: {path} not found", file=sys.stderr)
        return 1

    src = path.read_text(encoding="utf-8")
    if PATCH_TAG in src:
        print("already patched")
        return 0
    if MARKER not in src:
        print(
            "patch failed: requiresTransportSecurity() not found; Xray changed its check, "
            "update scripts/patch_xray.py",
            file=sys.stderr,
        )
        return 1

    patched = src.replace(
        MARKER,
        MARKER + "\n\t// EGN patch: TLS is optional, plaintext VLESS/Trojan is allowed.\n\treturn false\n",
        1,
    )
    path.write_text(patched, encoding="utf-8")
    print(f"patched {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
