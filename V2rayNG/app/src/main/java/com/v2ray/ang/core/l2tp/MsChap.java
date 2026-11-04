package com.v2ray.ang.core.l2tp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/** CHAP helpers for PPP: CHAP-MD5 (RFC 1994) and MS-CHAPv2 (RFC 2759), with a self-contained MD4. */
final class MsChap {
    private MsChap() {}

    static byte[] chapMd5(int id, byte[] secret, byte[] challenge) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update((byte) id);
        md.update(secret);
        md.update(challenge);
        return md.digest();
    }

    /** NT-Response (24 bytes) of MS-CHAPv2. */
    static byte[] ntResponse(byte[] authChallenge, byte[] peerChallenge, String user, String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(peerChallenge);
        sha.update(authChallenge);
        sha.update(user.getBytes(StandardCharsets.UTF_8));
        byte[] challenge = new byte[8];
        System.arraycopy(sha.digest(), 0, challenge, 0, 8);
        return challengeResponse(challenge, ntPasswordHash(password));
    }

    static byte[] ntPasswordHash(String password) {
        return md4(password.getBytes(StandardCharsets.UTF_16LE));
    }

    static byte[] challengeResponse(byte[] challenge, byte[] passwordHash) throws Exception {
        byte[] padded = new byte[21];
        System.arraycopy(passwordHash, 0, padded, 0, 16);
        byte[] out = new byte[24];
        for (int i = 0; i < 3; i++) {
            byte[] key = desKey(padded, i * 7);
            Cipher c = Cipher.getInstance("DES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "DES"));
            System.arraycopy(c.doFinal(challenge), 0, out, i * 8, 8);
        }
        return out;
    }

    /** 7 key bytes -> 8-byte DES key (parity bits are set to odd parity). */
    private static byte[] desKey(byte[] in, int off) {
        byte[] k = new byte[8];
        k[0] = (byte) ((in[off] & 0xFF) >> 1 << 1);
        k[1] = (byte) ((((in[off] & 0x01) << 6) | ((in[off + 1] & 0xFF) >> 2)) << 1);
        k[2] = (byte) ((((in[off + 1] & 0x03) << 5) | ((in[off + 2] & 0xFF) >> 3)) << 1);
        k[3] = (byte) ((((in[off + 2] & 0x07) << 4) | ((in[off + 3] & 0xFF) >> 4)) << 1);
        k[4] = (byte) ((((in[off + 3] & 0x0F) << 3) | ((in[off + 4] & 0xFF) >> 5)) << 1);
        k[5] = (byte) ((((in[off + 4] & 0x1F) << 2) | ((in[off + 5] & 0xFF) >> 6)) << 1);
        k[6] = (byte) ((((in[off + 5] & 0x3F) << 1) | ((in[off + 6] & 0xFF) >> 7)) << 1);
        k[7] = (byte) ((in[off + 6] & 0x7F) << 1);
        for (int i = 0; i < 8; i++) {
            int b = k[i] & 0xFE;
            k[i] = (byte) (Integer.bitCount(b) % 2 == 0 ? b | 1 : b);
        }
        return k;
    }

    // ── MD4 (RFC 1320) ──────────────────────────────────────────────────────────────────────────

    static byte[] md4(byte[] message) {
        int len = message.length;
        int padLen = (len % 64 < 56) ? 56 - len % 64 : 120 - len % 64;
        byte[] data = new byte[len + padLen + 8];
        System.arraycopy(message, 0, data, 0, len);
        data[len] = (byte) 0x80;
        long bits = (long) len * 8;
        for (int i = 0; i < 8; i++) data[len + padLen + i] = (byte) (bits >>> (8 * i));

        int a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        int[] x = new int[16];
        for (int off = 0; off < data.length; off += 64) {
            for (int i = 0; i < 16; i++) {
                x[i] = (data[off + i * 4] & 0xFF) | ((data[off + i * 4 + 1] & 0xFF) << 8)
                        | ((data[off + i * 4 + 2] & 0xFF) << 16) | ((data[off + i * 4 + 3] & 0xFF) << 24);
            }
            int aa = a, bb = b, cc = c, dd = d;
            int[] s1 = {3, 7, 11, 19};
            for (int i = 0; i < 16; i++) {
                int t = a + ((b & c) | (~b & d)) + x[i];
                t = Integer.rotateLeft(t, s1[i % 4]);
                a = d; d = c; c = b; b = t;
            }
            int[] s2 = {3, 5, 9, 13};
            int[] o2 = {0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15};
            for (int i = 0; i < 16; i++) {
                int t = a + ((b & c) | (b & d) | (c & d)) + x[o2[i]] + 0x5a827999;
                t = Integer.rotateLeft(t, s2[i % 4]);
                a = d; d = c; c = b; b = t;
            }
            int[] s3 = {3, 9, 11, 15};
            int[] o3 = {0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15};
            for (int i = 0; i < 16; i++) {
                int t = a + (b ^ c ^ d) + x[o3[i]] + 0x6ed9eba1;
                t = Integer.rotateLeft(t, s3[i % 4]);
                a = d; d = c; c = b; b = t;
            }
            a += aa; b += bb; c += cc; d += dd;
        }
        byte[] out = new byte[16];
        int[] r = {a, b, c, d};
        for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) out[i * 4 + j] = (byte) (r[i] >>> (8 * j));
        return out;
    }
}
