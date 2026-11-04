#!/bin/bash
# Cross-builds libopenconnect.so (Cisco AnyConnect / OpenConnect client, LGPL-2.1, with the JNI bindings
# built in) for every Android ABI, linked statically against OpenSSL and libxml2, and drops the result
# into V2rayNG/app/libs/<abi>/. Needs: ANDROID_NDK_HOME, autoconf automake libtool pkg-config cmake, a JDK
# (for jni.h). CI runs this; the output folder is cached.
set -o errexit -o nounset -o pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OC="$ROOT/third_party/openconnect"
OUT="$ROOT/V2rayNG/app/libs"
WORK="${OC_WORK:-$ROOT/oc-build}"
API=24
OPENSSL_TAG="${OPENSSL_TAG:-openssl-3.0.15}"
LIBXML2_TAG="${LIBXML2_TAG:-v2.11.9}"
NDK="${ANDROID_NDK_HOME:?ANDROID_NDK_HOME not set}"
TOOLBIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
JNI_INC="${JAVA_HOME:?JAVA_HOME not set}/include"
export PATH="$TOOLBIN:$PATH"
export ANDROID_NDK_ROOT="$NDK"
JOBS="$(nproc)"

mkdir -p "$WORK" "$OUT"
[ -d "$WORK/openssl-src" ] || git clone -q --depth 1 --branch "$OPENSSL_TAG" https://github.com/openssl/openssl.git "$WORK/openssl-src"
[ -d "$WORK/libxml2-src" ] || git clone -q --depth 1 --branch "$LIBXML2_TAG" https://github.com/GNOME/libxml2.git "$WORK/libxml2-src"
if [ ! -d "$WORK/oc-src" ]; then
  cp -r "$OC" "$WORK/oc-src"
  rm -rf "$WORK/oc-src/.git"
  (cd "$WORK/oc-src" && sh autogen.sh)
fi

build_abi() {
  local abi="$1" ossl_target="$2" triple="$3" host="$4"
  local P="$WORK/prefix-$abi"
  echo "=== $abi ==="
  mkdir -p "$P"

  # OpenSSL
  if [ ! -f "$P/lib/libssl.a" ]; then
    rm -rf "$WORK/openssl-$abi"; mkdir -p "$WORK/openssl-$abi"
    (cd "$WORK/openssl-$abi" &&
      "$WORK/openssl-src/Configure" "$ossl_target" -D__ANDROID_API__=$API no-shared no-tests no-engine no-comp no-ssl3 \
        -fPIC --prefix="$P" --openssldir="$P/ssl" &&
      make -j"$JOBS" build_libs &&
      make install_dev)
  fi
  [ -f "$P/lib/libssl.a" ] || [ -f "$P/lib64/libssl.a" ] || { echo "OpenSSL missing"; exit 1; }
  local SSLLIB="$P/lib"; [ -f "$SSLLIB/libssl.a" ] || SSLLIB="$P/lib64"

  # libxml2
  if [ ! -f "$P/lib/libxml2.a" ]; then
    rm -rf "$WORK/libxml2-$abi"
    cmake -S "$WORK/libxml2-src" -B "$WORK/libxml2-$abi" -G "Unix Makefiles" \
      -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" -DANDROID_ABI="$abi" -DANDROID_PLATFORM=android-$API \
      -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      -DCMAKE_INSTALL_PREFIX="$P" \
      -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ICONV=OFF -DLIBXML2_WITH_ZLIB=OFF \
      -DLIBXML2_WITH_PROGRAMS=OFF -DLIBXML2_WITH_TESTS=OFF -DLIBXML2_WITH_HTTP=OFF -DLIBXML2_WITH_FTP=OFF
    cmake --build "$WORK/libxml2-$abi" -j"$JOBS"
    cmake --install "$WORK/libxml2-$abi"
  fi
  [ -f "$P/lib/libxml2.a" ] || { echo "libxml2 missing"; exit 1; }

  # OpenConnect (+ JNI)
  export CC="$TOOLBIN/${triple}${API}-clang" AR="$TOOLBIN/llvm-ar" RANLIB="$TOOLBIN/llvm-ranlib" STRIP="$TOOLBIN/llvm-strip"
  rm -rf "$WORK/oc-$abi"; mkdir -p "$WORK/oc-$abi"
  (cd "$WORK/oc-$abi" &&
    OPENSSL_CFLAGS="-I$P/include" OPENSSL_LIBS="$SSLLIB/libssl.a $SSLLIB/libcrypto.a -ldl -lz" \
    LIBXML2_CFLAGS="-I$P/include/libxml2 -DLIBXML_STATIC" LIBXML2_LIBS="$P/lib/libxml2.a -lz -lm" \
    CFLAGS="-O2 -fPIC -Wno-deprecated-declarations -I$JNI_INC/linux" \
    "$WORK/oc-src/configure" --host="$host" --prefix="$P/oc" \
      --enable-shared --disable-static --enable-jni-standalone --with-java="$JNI_INC" \
      --with-openssl --without-gnutls --without-lz4 --without-stoken --without-libproxy --without-libpcsclite \
      --without-libpskc --without-gssapi --disable-nls --with-vpnc-script=/system/bin/true &&
    make -j"$JOBS" libopenconnect.la &&
    make install-libLTLIBRARIES)
  mkdir -p "$OUT/$abi"
  cp -L "$P/oc/lib/libopenconnect.so" "$OUT/$abi/libopenconnect.so"
  "$STRIP" --strip-unneeded "$OUT/$abi/libopenconnect.so"
  ls -l "$OUT/$abi/libopenconnect.so"
}

build_abi arm64-v8a   android-arm64  aarch64-linux-android   aarch64-linux-android
build_abi armeabi-v7a android-arm    armv7a-linux-androideabi arm-linux-androideabi
build_abi x86_64      android-x86_64 x86_64-linux-android    x86_64-linux-android
build_abi x86         android-x86    i686-linux-android      i686-linux-android
