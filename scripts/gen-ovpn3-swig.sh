#!/bin/bash
# Generates the Java/C++ SWIG bindings of the OpenVPN 3 client (net.openvpn.ovpn3.*).
# Needs: swig (apt install swig). Run before the Gradle build; CI does this automatically.
set -o errexit
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
O3="$ROOT/third_party/openvpn3"
APP="$ROOT/V2rayNG/app/src/main"
JAVA_OUT="$APP/java/net/openvpn/ovpn3"
CPP_OUT="$APP/cpp/gen"
rm -rf "$JAVA_OUT" "$CPP_OUT"
mkdir -p "$JAVA_OUT" "$CPP_OUT"
swig -c++ -java -package net.openvpn.ovpn3 \
  -outdir "$JAVA_OUT" -o "$CPP_OUT/ovpncli_wrap.cxx" \
  -DOPENVPN_PLATFORM_ANDROID \
  -I"$O3/client" -I"$O3" \
  "$O3/client/ovpncli.i"
ls "$JAVA_OUT"
