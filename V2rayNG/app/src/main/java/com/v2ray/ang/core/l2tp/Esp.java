package com.v2ray.ang.core.l2tp;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** ESP (RFC 4303) in transport mode, as carried in UDP port 4500: CBC encryption plus truncated HMAC. */
final class Esp {
    final int inSpi;
    final int outSpi;
    private final String cipherName;
    private final String keyAlg;
    private final int block;
    private final byte[] encIn, encOut, authIn, authOut;
    private final String macName;
    private final int icvLen;
    private final SecureRandom rnd = new SecureRandom();
    private long seq = 0;
    private Cipher encCipher, decCipher;
    private Mac encMac, decMac;

    Esp(Ike1.EspSa sa) {
        this.inSpi = sa.inSpi;
        this.outSpi = sa.outSpi;
        this.keyAlg = sa.enc.keyAlg;
        this.cipherName = sa.enc.cipher + "/CBC/NoPadding";
        this.block = sa.enc.block;
        this.encIn = sa.encKeyIn;
        this.encOut = sa.encKeyOut;
        this.authIn = sa.authKeyIn;
        this.authOut = sa.authKeyOut;
        this.macName = sa.auth.mac;
        this.icvLen = sa.auth.icvLen;
    }

    /** @param inner the transported datagram (UDP header + payload); @return the full ESP packet. */
    synchronized byte[] encrypt(byte[] inner, int nextHeader) throws GeneralSecurityException {
        int padLen = (block - ((inner.length + 2) % block)) % block;
        byte[] plain = new byte[inner.length + padLen + 2];
        System.arraycopy(inner, 0, plain, 0, inner.length);
        for (int i = 0; i < padLen; i++) plain[inner.length + i] = (byte) (i + 1);
        plain[plain.length - 2] = (byte) padLen;
        plain[plain.length - 1] = (byte) nextHeader;

        byte[] iv = new byte[block];
        rnd.nextBytes(iv);
        if (encCipher == null) encCipher = Cipher.getInstance(cipherName);
        Cipher c = encCipher;
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encOut, keyAlg), new IvParameterSpec(iv));
        byte[] ct = c.doFinal(plain);

        seq++;
        byte[] pkt = new byte[8 + block + ct.length + icvLen];
        putInt(pkt, 0, outSpi);
        putInt(pkt, 4, (int) seq);
        System.arraycopy(iv, 0, pkt, 8, block);
        System.arraycopy(ct, 0, pkt, 8 + block, ct.length);
        int authLen = 8 + block + ct.length;
        if (encMac == null) { encMac = Mac.getInstance(macName); encMac.init(new SecretKeySpec(authOut, macName)); }
        Mac mac = encMac;
        mac.update(pkt, 0, authLen);
        System.arraycopy(mac.doFinal(), 0, pkt, authLen, icvLen);
        return pkt;
    }

    /** @return the transported datagram, or null when the packet is not ours / fails authentication. */
    synchronized byte[] decrypt(byte[] pkt, int len, int[] nextHeaderOut) throws GeneralSecurityException {
        int minLen = 8 + block + block + icvLen;
        if (len < minLen) return null;
        if (getInt(pkt, 0) != inSpi) return null;
        int authLen = len - icvLen;
        if (decMac == null) { decMac = Mac.getInstance(macName); decMac.init(new SecretKeySpec(authIn, macName)); }
        Mac mac = decMac;
        mac.update(pkt, 0, authLen);
        byte[] icv = Arrays.copyOf(mac.doFinal(), icvLen);
        if (!MessageDigest.isEqual(icv, Arrays.copyOfRange(pkt, authLen, len))) return null;

        int ctLen = authLen - 8 - block;
        if (ctLen <= 0 || ctLen % block != 0) return null;
        if (decCipher == null) decCipher = Cipher.getInstance(cipherName);
        Cipher c = decCipher;
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encIn, keyAlg), new IvParameterSpec(pkt, 8, block));
        byte[] plain = c.doFinal(pkt, 8 + block, ctLen);
        int padLen = plain[plain.length - 2] & 0xFF;
        int next = plain[plain.length - 1] & 0xFF;
        int innerLen = plain.length - 2 - padLen;
        if (innerLen < 0) return null;
        if (nextHeaderOut != null) nextHeaderOut[0] = next;
        return Arrays.copyOf(plain, innerLen);
    }

    static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    static int getInt(byte[] b, int off) {
        return ((b[off] & 0xFF) << 24) | ((b[off + 1] & 0xFF) << 16) | ((b[off + 2] & 0xFF) << 8) | (b[off + 3] & 0xFF);
    }
}
