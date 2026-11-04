package com.v2ray.ang.core.l2tp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * IKEv1 initiator for L2TP/IPsec (RFC 2409, RFC 3947): Main Mode with a pre-shared key, then one Quick Mode
 * that sets up an ESP security association in UDP-encapsulated transport mode for UDP port 1701.
 * Raw ESP cannot be sent from an app, so NAT traversal is always negotiated.
 */
final class Ike1 {

    interface Protector {
        void protect(DatagramSocket socket) throws IOException;
    }

    interface Log {
        void log(String line);
    }

    static final class IkeException extends IOException {
        IkeException(String m) {
            super(m);
        }
    }

    // ── algorithm tables ───────────────────────────────────────────────────────────────────────

    static final class EncAlg {
        final String name, cipher, keyAlg;
        final int ikeId, espId, keyBytes, block;

        EncAlg(String name, String cipher, String keyAlg, int ikeId, int espId, int keyBytes, int block) {
            this.name = name; this.cipher = cipher; this.keyAlg = keyAlg;
            this.ikeId = ikeId; this.espId = espId; this.keyBytes = keyBytes; this.block = block;
        }

        boolean isAes() {
            return keyAlg.equals("AES");
        }
    }

    static final EncAlg AES256 = new EncAlg("AES-256", "AES", "AES", 7, 12, 32, 16);
    static final EncAlg AES128 = new EncAlg("AES-128", "AES", "AES", 7, 12, 16, 16);
    static final EncAlg TRIPLE_DES = new EncAlg("3DES", "DESede", "DESede", 5, 3, 24, 8);
    static final EncAlg[] ENCS = {AES256, AES128, TRIPLE_DES};

    static final class HashAlg {
        final String name, digest, mac;
        final int ikeId, espAuthId, len, icvLen;

        HashAlg(String name, String digest, String mac, int ikeId, int espAuthId, int len, int icvLen) {
            this.name = name; this.digest = digest; this.mac = mac;
            this.ikeId = ikeId; this.espAuthId = espAuthId; this.len = len; this.icvLen = icvLen;
        }
    }

    static final HashAlg SHA1 = new HashAlg("SHA1", "SHA-1", "HmacSHA1", 2, 2, 20, 12);
    static final HashAlg SHA256 = new HashAlg("SHA256", "SHA-256", "HmacSHA256", 4, 5, 32, 16);
    static final HashAlg MD5 = new HashAlg("MD5", "MD5", "HmacMD5", 1, 1, 16, 12);
    static final HashAlg[] HASHES = {SHA1, SHA256, MD5};
    static final int[] GROUPS = {14, 2, 5};

    /** Result of the negotiation: everything the ESP layer needs. */
    static final class EspSa {
        int inSpi, outSpi;
        EncAlg enc;
        HashAlg auth;
        byte[] encKeyIn, encKeyOut, authKeyIn, authKeyOut;
        byte[] localIp;
        DatagramSocket socket; // connected to server:4500
    }

    // ── constants ──────────────────────────────────────────────────────────────────────────────

    private static final int NP_SA = 1, NP_P = 2, NP_T = 3, NP_KE = 4, NP_ID = 5, NP_HASH = 8, NP_NONCE = 10,
            NP_NOTIFY = 11, NP_VID = 13;
    private static final int EX_MAIN = 2, EX_INFO = 5, EX_QUICK = 32;

    private final InetAddress server;
    private final byte[] psk;
    private final Protector protector;
    private final Log log;
    private final SecureRandom rnd = new SecureRandom();

    // negotiated state
    private EncAlg enc;
    private HashAlg hash;
    private int group;
    private int natdType = 20, natoaType = 21;
    private byte[] skeyidA, skeyidD, skeyidE, encKey;
    private byte[] ivState; // last CBC block of the latest phase 1 message

    Ike1(InetAddress server, byte[] psk, Protector protector, Log log) {
        this.server = server;
        this.psk = psk;
        this.protector = protector;
        this.log = log;
    }

    // ── packet helpers ─────────────────────────────────────────────────────────────────────────

    private static final class P {
        final int type;
        final byte[] body;

        P(int type, byte[] body) {
            this.type = type;
            this.body = body;
        }
    }

    private static final class Pld {
        int type;
        byte[] raw; // with the 4 byte generic header
        byte[] body;
    }

    private static final class Msg {
        byte[] ckyI = new byte[8], ckyR = new byte[8];
        int next, exch, flags, mid;
        byte[] data;
    }

    private static byte[] payloads(List<P> ps) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (int i = 0; i < ps.size(); i++) {
            int next = i + 1 < ps.size() ? ps.get(i + 1).type : 0;
            o.write(next);
            o.write(0);
            w16(o, 4 + ps.get(i).body.length);
            o.write(ps.get(i).body, 0, ps.get(i).body.length);
        }
        return o.toByteArray();
    }

    private static byte[] isakmp(byte[] ckyI, byte[] ckyR, int next, int exch, int flags, int mid, byte[] data) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(ckyI, 0, 8);
        o.write(ckyR, 0, 8);
        o.write(next);
        o.write(0x10);
        o.write(exch);
        o.write(flags);
        w32(o, mid);
        w32(o, 28 + data.length);
        o.write(data, 0, data.length);
        return o.toByteArray();
    }

    private static void w16(ByteArrayOutputStream o, int v) {
        o.write(v >>> 8);
        o.write(v);
    }

    private static void w32(ByteArrayOutputStream o, int v) {
        o.write(v >>> 24);
        o.write(v >>> 16);
        o.write(v >>> 8);
        o.write(v);
    }

    private static void tv(ByteArrayOutputStream o, int type, int value) {
        w16(o, 0x8000 | type);
        w16(o, value);
    }

    private static int r16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static Msg parseMsg(byte[] b, int len) {
        if (len < 28) return null;
        Msg m = new Msg();
        System.arraycopy(b, 0, m.ckyI, 0, 8);
        System.arraycopy(b, 8, m.ckyR, 0, 8);
        m.next = b[16] & 0xFF;
        m.exch = b[18] & 0xFF;
        m.flags = b[19] & 0xFF;
        m.mid = Esp.getInt(b, 20);
        int total = Esp.getInt(b, 24);
        if (total < 28 || total > len) total = len;
        m.data = Arrays.copyOfRange(b, 28, total);
        return m;
    }

    private static List<Pld> parsePayloads(byte[] data, int first) {
        List<Pld> out = new ArrayList<>();
        int type = first, off = 0;
        while (type != 0 && off + 4 <= data.length) {
            int next = data[off] & 0xFF;
            int len = r16(data, off + 2);
            if (len < 4 || off + len > data.length) break;
            Pld p = new Pld();
            p.type = type;
            p.raw = Arrays.copyOfRange(data, off, off + len);
            p.body = Arrays.copyOfRange(data, off + 4, off + len);
            out.add(p);
            type = next;
            off += len;
        }
        return out;
    }

    private static Pld find(List<Pld> l, int type) {
        for (Pld p : l) if (p.type == type) return p;
        return null;
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] o = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, o, off, p.length);
            off += p.length;
        }
        return o;
    }

    private byte[] rand(int n) {
        byte[] b = new byte[n];
        rnd.nextBytes(b);
        return b;
    }

    private static byte[] be(int v) {
        return new byte[]{(byte) (v >>> 24), (byte) (v >>> 16), (byte) (v >>> 8), (byte) v};
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    // ── crypto ─────────────────────────────────────────────────────────────────────────────────

    private byte[] prf(byte[] key, byte[]... data) throws IOException {
        try {
            Mac m = Mac.getInstance(hash.mac);
            m.init(new SecretKeySpec(key, hash.mac));
            for (byte[] d : data) m.update(d);
            return m.doFinal();
        } catch (Exception e) {
            throw new IkeException("crypto: " + e);
        }
    }

    private byte[] digest(byte[]... data) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance(hash.digest);
            for (byte[] d : data) md.update(d);
            return md.digest();
        } catch (Exception e) {
            throw new IkeException("crypto: " + e);
        }
    }

    private byte[] cbc(boolean encrypt, byte[] iv, byte[] in) throws IOException {
        try {
            Cipher c = Cipher.getInstance(enc.cipher + "/CBC/NoPadding");
            c.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, enc.keyAlg), new IvParameterSpec(iv));
            return c.doFinal(in);
        } catch (Exception e) {
            throw new IkeException("crypto: " + e);
        }
    }

    private byte[] md5(String s) throws IOException {
        try {
            return MessageDigest.getInstance("MD5").digest(s.getBytes("US-ASCII"));
        } catch (Exception e) {
            throw new IkeException("crypto: " + e);
        }
    }

    /** Key expansion of RFC 2409 appendix B / quick mode KEYMAT: K1 = prf(key, seed), Kn = prf(key, Kn-1 | seed). */
    private byte[] expand(byte[] key, byte[] seed, int need) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        while (o.size() < need) {
            prev = prf(key, prev, seed);
            o.write(prev, 0, prev.length);
        }
        return Arrays.copyOf(o.toByteArray(), need);
    }

    private static byte[] fixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }

    // ── transport ──────────────────────────────────────────────────────────────────────────────

    private DatagramSocket open(int port) throws IOException {
        DatagramSocket s = new DatagramSocket();
        protector.protect(s);
        s.connect(server, port);
        return s;
    }

    private void send(DatagramSocket s, boolean marker, byte[] msg) throws IOException {
        byte[] out = marker ? concat(new byte[4], msg) : msg;
        s.send(new DatagramPacket(out, out.length));
    }

    /** Sends [msg] and waits for the answer of the same exchange; retransmits a few times. */
    private Msg exchange(DatagramSocket s, boolean marker, byte[] msg, byte[] ckyI, int mid, String what) throws IOException {
        byte[] buf = new byte[4096];
        for (int attempt = 0; attempt < 4; attempt++) {
            send(s, marker, msg);
            long deadline = System.currentTimeMillis() + 4000;
            while (true) {
                long left = deadline - System.currentTimeMillis();
                if (left <= 0) break;
                s.setSoTimeout((int) left);
                DatagramPacket p = new DatagramPacket(buf, buf.length);
                try {
                    s.receive(p);
                } catch (SocketTimeoutException e) {
                    break;
                }
                int off = 0, len = p.getLength();
                if (marker) {
                    if (len < 4 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 0) continue; // ESP or keepalive
                    off = 4;
                }
                Msg m = parseMsg(Arrays.copyOfRange(buf, off, off + len - off), len - off);
                if (m == null || !Arrays.equals(m.ckyI, ckyI)) continue;
                if (m.exch == EX_INFO && (m.flags & 1) == 0) {
                    String err = notifyError(m);
                    if (err != null) throw new IkeException(what + ": server answered " + err);
                    continue;
                }
                if (m.mid != mid) continue;
                return m;
            }
            log.log("IKE: no answer to " + what + ", retry " + (attempt + 1));
        }
        throw new IkeException("The server did not answer (" + what + "). Check the address and that UDP 500/4500 are open.");
    }

    private String notifyError(Msg m) {
        for (Pld p : parsePayloads(m.data, m.next)) {
            if (p.type == NP_NOTIFY && p.body.length >= 8) {
                int t = r16(p.body, 6);
                if (t < 16384) return notifyName(t);
            }
        }
        return null;
    }

    private static String notifyName(int t) {
        switch (t) {
            case 1: return "INVALID-PAYLOAD-TYPE";
            case 5: return "INVALID-ID-INFORMATION";
            case 7: return "INVALID-EXCHANGE-TYPE";
            case 9: return "INVALID-FLAGS";
            case 14: return "NO-PROPOSAL-CHOSEN (the server accepts none of the offered algorithms)";
            case 17: return "INVALID-KEY-INFORMATION";
            case 18: return "INVALID-ID-INFORMATION";
            case 23: return "AUTHENTICATION-FAILED (wrong secret?)";
            case 24: return "INVALID-HASH-INFORMATION (wrong secret?)";
            default: return "notify " + t;
        }
    }

    // ── negotiation ────────────────────────────────────────────────────────────────────────────

    private boolean probeOnly;
    private long probeMs = -1;

    /** Measures the round trip of the first IKE message (the server answers with its chosen proposal). */
    static long probe(InetAddress server, Protector protector, Log log) throws IOException {
        Ike1 ike = new Ike1(server, new byte[0], protector, log);
        ike.probeOnly = true;
        ike.negotiate();
        return ike.probeMs;
    }

    EspSa negotiate() throws IOException {
        DatagramSocket s500 = open(500);
        DatagramSocket s4500 = null;
        try {
            byte[] localIp = s500.getLocalAddress().getAddress();
            if (localIp.length != 4) throw new IkeException("Only IPv4 servers are supported");
            byte[] ckyI = rand(8);

            // ---- Main Mode 1/2: proposals
            ByteArrayOutputStream tr = new ByteArrayOutputStream();
            List<int[]> offers = new ArrayList<>();
            for (int e = 0; e < ENCS.length; e++)
                for (int h = 0; h < HASHES.length; h++)
                    for (int g = 0; g < GROUPS.length; g++) offers.add(new int[]{e, h, g});
            int n = offers.size();
            for (int i = 0; i < n; i++) {
                int[] o = offers.get(i);
                ByteArrayOutputStream at = new ByteArrayOutputStream();
                tv(at, 1, ENCS[o[0]].ikeId);
                if (ENCS[o[0]].isAes()) tv(at, 14, ENCS[o[0]].keyBytes * 8);
                tv(at, 2, HASHES[o[1]].ikeId);
                tv(at, 3, 1); // pre-shared key
                tv(at, 4, GROUPS[o[2]]);
                tv(at, 11, 1);
                tv(at, 12, 28800);
                byte[] attrs = at.toByteArray();
                tr.write(i + 1 < n ? NP_T : 0);
                tr.write(0);
                w16(tr, 8 + attrs.length);
                tr.write(i + 1);
                tr.write(1); // KEY_IKE
                tr.write(0);
                tr.write(0);
                tr.write(attrs, 0, attrs.length);
            }
            byte[] trb = tr.toByteArray();
            ByteArrayOutputStream prop = new ByteArrayOutputStream();
            prop.write(0);
            prop.write(0);
            w16(prop, 8 + trb.length);
            prop.write(1); // proposal #1
            prop.write(1); // PROTO_ISAKMP
            prop.write(0); // SPI size
            prop.write(n);
            prop.write(trb, 0, trb.length);
            byte[] saBody = concat(be(1), be(1), prop.toByteArray()); // DOI = IPsec, situation = identity only

            List<P> m1 = new ArrayList<>();
            m1.add(new P(NP_SA, saBody));
            m1.add(new P(NP_VID, md5("RFC 3947")));
            m1.add(new P(NP_VID, md5("draft-ietf-ipsec-nat-t-ike-02\n")));
            byte[] msg1 = isakmp(ckyI, new byte[8], NP_SA, EX_MAIN, 0, 0, payloads(m1));
            long t0 = System.nanoTime();
            Msg r1 = exchange(s500, false, msg1, ckyI, 0, "main mode 1");
            if (probeOnly) {
                probeMs = Math.max(1, (System.nanoTime() - t0) / 1_000_000);
                return null;
            }
            byte[] ckyR = r1.ckyR;
            List<Pld> l1 = parsePayloads(r1.data, r1.next);
            Pld sa = find(l1, NP_SA);
            if (sa == null) throw new IkeException("The server's answer has no proposal");
            chooseTransform(sa.body);
            log.log("IKE phase 1: " + enc.name + ", " + hash.name + ", DH group " + group);

            boolean rfc = false, draft = false;
            byte[] vRfc = md5("RFC 3947"), vDraft = md5("draft-ietf-ipsec-nat-t-ike-02\n");
            for (Pld p : l1) {
                if (p.type != NP_VID) continue;
                if (Arrays.equals(p.body, vRfc)) rfc = true;
                if (Arrays.equals(p.body, vDraft)) draft = true;
            }
            if (!rfc && !draft) {
                throw new IkeException("The server does not support NAT traversal (UDP encapsulation), which is required here");
            }
            natdType = rfc ? 20 : 130;
            natoaType = rfc ? 21 : 131;

            // ---- Main Mode 3/4: key exchange
            BigInteger p = DhGroups.prime(group);
            int plen = (p.bitLength() + 7) / 8;
            BigInteger x = new BigInteger(256, rnd).setBit(255);
            byte[] xi = fixed(DhGroups.G.modPow(x, p), plen);
            byte[] ni = rand(24);
            byte[] natd1 = digest(ckyI, ckyR, server.getAddress(), new byte[]{0x01, (byte) 0xF4});
            byte[] natd2 = digest(ckyI, ckyR, localIp, new byte[]{0x01, (byte) 0xF4});
            List<P> m3 = new ArrayList<>();
            m3.add(new P(NP_KE, xi));
            m3.add(new P(NP_NONCE, ni));
            m3.add(new P(natdType, natd1));
            m3.add(new P(natdType, natd2));
            byte[] msg3 = isakmp(ckyI, ckyR, NP_KE, EX_MAIN, 0, 0, payloads(m3));
            Msg r3 = exchange(s500, false, msg3, ckyI, 0, "main mode 3");
            List<Pld> l3 = parsePayloads(r3.data, r3.next);
            Pld ke = find(l3, NP_KE), nonce = find(l3, NP_NONCE);
            if (ke == null || nonce == null) throw new IkeException("The server's key exchange answer is incomplete");
            byte[] yr = fixed(new BigInteger(1, ke.body), plen);
            byte[] nr = nonce.body;
            byte[] gxy = fixed(new BigInteger(1, ke.body).modPow(x, p), plen);

            byte[] skeyid = prf(psk, ni, nr);
            skeyidD = prf(skeyid, gxy, ckyI, ckyR, new byte[]{0});
            skeyidA = prf(skeyid, skeyidD, gxy, ckyI, ckyR, new byte[]{1});
            skeyidE = prf(skeyid, skeyidA, gxy, ckyI, ckyR, new byte[]{2});
            encKey = skeyidE.length >= enc.keyBytes ? Arrays.copyOf(skeyidE, enc.keyBytes) : expand(skeyidE, new byte[]{0}, enc.keyBytes);
            // RFC 2409 appendix B: K1 = prf(SKEYID_e, 0), K2 = prf(SKEYID_e, K1) ...
            if (skeyidE.length < enc.keyBytes) {
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                byte[] k = prf(skeyidE, new byte[]{0});
                o.write(k, 0, k.length);
                while (o.size() < enc.keyBytes) {
                    k = prf(skeyidE, k);
                    o.write(k, 0, k.length);
                }
                encKey = Arrays.copyOf(o.toByteArray(), enc.keyBytes);
            }
            byte[] iv0 = Arrays.copyOf(digest(xi, yr), enc.block);

            // ---- Main Mode 5/6: authentication, from here on on port 4500
            s4500 = open(4500);
            byte[] idBody = concat(new byte[]{1, 0, 0, 0}, localIp); // ID_IPV4_ADDR
            byte[] hashI = prf(skeyid, xi, yr, ckyI, ckyR, saBody, idBody);
            List<P> m5 = new ArrayList<>();
            m5.add(new P(NP_ID, idBody));
            m5.add(new P(NP_HASH, hashI));
            byte[] ct5 = cbc(true, iv0, pad(payloads(m5), enc.block));
            byte[] msg5 = isakmp(ckyI, ckyR, NP_ID, EX_MAIN, 1, 0, ct5);
            ivState = Arrays.copyOfRange(ct5, ct5.length - enc.block, ct5.length);
            Msg r5 = exchange(s4500, true, msg5, ckyI, 0, "main mode 5");
            if ((r5.flags & 1) == 0) throw new IkeException("The server's identity answer is not encrypted");
            byte[] pt6 = cbc(false, ivState, trimBlocks(r5.data, enc.block));
            List<Pld> l6 = parsePayloads(pt6, r5.next);
            Pld idr = find(l6, NP_ID), hr = find(l6, NP_HASH);
            if (idr == null || hr == null) throw new IkeException("The server's identity answer is incomplete");
            byte[] expectR = prf(skeyid, yr, xi, ckyR, ckyI, saBody, idr.body);
            if (!MessageDigest.isEqual(expectR, hr.body)) {
                throw new IkeException("The server's authentication hash does not match: the secret (PSK) is probably wrong");
            }
            ivState = Arrays.copyOfRange(r5.data, trimBlocks(r5.data, enc.block).length - enc.block, trimBlocks(r5.data, enc.block).length);
            log.log("IKE phase 1 done");

            // ---- Quick Mode
            return quickMode(s500, s4500, ckyI, ckyR, localIp);
        } catch (IOException | RuntimeException e) {
            if (s4500 != null) s4500.close();
            throw e instanceof IOException ? (IOException) e : new IkeException(String.valueOf(e));
        } finally {
            s500.close();
        }
    }

    private static byte[] pad(byte[] in, int block) {
        int n = (block - in.length % block) % block;
        return n == 0 ? in : Arrays.copyOf(in, in.length + n);
    }

    private static byte[] trimBlocks(byte[] in, int block) {
        int n = in.length - in.length % block;
        return n == in.length ? in : Arrays.copyOf(in, n);
    }

    private void chooseTransform(byte[] saBody) throws IOException {
        // DOI(4) SIT(4) proposal: next rsv len(2) pnum proto spisz ntrans [spi] transform: next rsv len(2) tnum id rsv(2) attrs
        if (saBody.length < 8 + 8 + 8) throw new IkeException("The server's proposal is malformed");
        int off = 8;
        int spiSize = saBody[off + 6] & 0xFF;
        off += 8 + spiSize;
        int len = r16(saBody, off + 2);
        Map<Integer, Integer> a = attrs(saBody, off + 8, Math.min(off + len, saBody.length));
        enc = null;
        Integer e = a.get(1), kl = a.get(14), h = a.get(2), g = a.get(4);
        if (e == null || h == null || g == null) throw new IkeException("The server chose an incomplete transform");
        for (EncAlg c : ENCS) {
            if (c.ikeId == e && (!c.isAes() || (kl != null && kl == c.keyBytes * 8))) enc = c;
        }
        hash = null;
        for (HashAlg c : HASHES) if (c.ikeId == h) hash = c;
        group = g;
        if (enc == null || hash == null || DhGroups.prime(group) == null) {
            throw new IkeException("The server chose an unsupported transform (enc " + e + ", hash " + h + ", group " + g + ")");
        }
    }

    private static Map<Integer, Integer> attrs(byte[] b, int off, int end) {
        Map<Integer, Integer> m = new HashMap<>();
        while (off + 4 <= end) {
            int t = r16(b, off);
            if ((t & 0x8000) != 0) {
                m.put(t & 0x7FFF, r16(b, off + 2));
                off += 4;
            } else {
                int l = r16(b, off + 2);
                int v = 0;
                for (int i = 0; i < l && i < 4 && off + 4 + i < end; i++) v = (v << 8) | (b[off + 4 + i] & 0xFF);
                m.put(t, v);
                off += 4 + l;
            }
        }
        return m;
    }

    // ── quick mode ─────────────────────────────────────────────────────────────────────────────

    private EspSa quickMode(DatagramSocket s500, DatagramSocket s4500, byte[] ckyI, byte[] ckyR, byte[] localIp) throws IOException {
        int mid = rnd.nextInt();
        if (mid == 0) mid = 1;
        int inSpi = rnd.nextInt() | 0x100;
        byte[] ni = rand(24);

        // ESP proposal: every encryption/auth combination as a separate transform
        ByteArrayOutputStream tr = new ByteArrayOutputStream();
        List<int[]> offers = new ArrayList<>();
        for (int e = 0; e < ENCS.length; e++) for (int h = 0; h < HASHES.length; h++) offers.add(new int[]{e, h});
        int n = offers.size();
        int encap = natdType == 20 ? 4 : 61444; // UDP-encapsulated transport mode
        for (int i = 0; i < n; i++) {
            EncAlg e = ENCS[offers.get(i)[0]];
            HashAlg h = HASHES[offers.get(i)[1]];
            ByteArrayOutputStream at = new ByteArrayOutputStream();
            tv(at, 1, 1);
            tv(at, 2, 3600);
            tv(at, 4, encap);
            tv(at, 5, h.espAuthId);
            if (e.isAes()) tv(at, 6, e.keyBytes * 8);
            byte[] attrs = at.toByteArray();
            tr.write(i + 1 < n ? NP_T : 0);
            tr.write(0);
            w16(tr, 8 + attrs.length);
            tr.write(i + 1);
            tr.write(e.espId);
            tr.write(0);
            tr.write(0);
            tr.write(attrs, 0, attrs.length);
        }
        byte[] trb = tr.toByteArray();
        ByteArrayOutputStream prop = new ByteArrayOutputStream();
        prop.write(0);
        prop.write(0);
        w16(prop, 8 + 4 + trb.length);
        prop.write(1); // proposal #1
        prop.write(3); // PROTO_IPSEC_ESP
        prop.write(4); // SPI size
        prop.write(n);
        prop.write(be(inSpi), 0, 4);
        prop.write(trb, 0, trb.length);
        byte[] saBody = concat(be(1), be(1), prop.toByteArray());

        byte[] srv = server.getAddress();
        byte[] idci = concat(new byte[]{1, 17, 0x06, (byte) 0xA5}, localIp); // IPv4, UDP, port 1701
        byte[] idcr = concat(new byte[]{1, 17, 0x06, (byte) 0xA5}, srv);
        List<P> rest = new ArrayList<>();
        rest.add(new P(NP_SA, saBody));
        rest.add(new P(NP_NONCE, ni));
        rest.add(new P(NP_ID, idci));
        rest.add(new P(NP_ID, idcr));
        rest.add(new P(natoaType, concat(new byte[]{1, 0, 0, 0}, localIp)));
        rest.add(new P(natoaType, concat(new byte[]{1, 0, 0, 0}, srv)));
        byte[] restBytes = payloads(rest);
        byte[] hash1 = prf(skeyidA, be(mid), restBytes);
        List<P> all = new ArrayList<>();
        all.add(new P(NP_HASH, hash1));
        all.addAll(rest);

        byte[] iv = Arrays.copyOf(digest(ivState, be(mid)), enc.block);
        byte[] ct1 = cbc(true, iv, pad(payloads(all), enc.block));
        byte[] msg = isakmp(ckyI, ckyR, NP_HASH, EX_QUICK, 1, mid, ct1);
        byte[] lastOut = Arrays.copyOfRange(ct1, ct1.length - enc.block, ct1.length);

        Msg r = exchange(s4500, true, msg, ckyI, mid, "quick mode 1");
        if ((r.flags & 1) == 0) throw new IkeException("The server's quick mode answer is not encrypted");
        byte[] rct = trimBlocks(r.data, enc.block);
        byte[] rpt = cbc(false, lastOut, rct);
        List<Pld> rl = parsePayloads(rpt, r.next);
        Pld h2 = find(rl, NP_HASH), sa2 = find(rl, NP_SA), nr2 = find(rl, NP_NONCE);
        if (h2 == null || sa2 == null || nr2 == null) throw new IkeException("The server's quick mode answer is incomplete");
        // HASH(2) = prf(SKEYID_a, M-ID | Ni_b | everything after the hash payload)
        int hashLen = h2.raw.length;
        byte[] afterHash = Arrays.copyOfRange(rpt, hashLen, endOfChain(rpt));
        byte[] expect = prf(skeyidA, be(mid), ni, afterHash);
        if (!MessageDigest.isEqual(expect, h2.body)) throw new IkeException("Quick mode: the server's hash does not match");

        // chosen ESP transform
        byte[] sb = sa2.body;
        int off = 8;
        int spiSize = sb[off + 6] & 0xFF;
        if (spiSize != 4) throw new IkeException("The server did not return an ESP SPI");
        int outSpi = Esp.getInt(sb, off + 8);
        off += 8 + spiSize;
        int espId = sb[off + 5] & 0xFF;
        int tlen = r16(sb, off + 2);
        Map<Integer, Integer> a = attrs(sb, off + 8, Math.min(off + tlen, sb.length));
        EncAlg ce = null;
        Integer kl = a.get(6), au = a.get(5);
        for (EncAlg c : ENCS) if (c.espId == espId && (!c.isAes() || (kl != null && kl == c.keyBytes * 8))) ce = c;
        HashAlg ca = null;
        if (au != null) for (HashAlg c : HASHES) if (c.espAuthId == au) ca = c;
        if (ce == null || ca == null) throw new IkeException("The server chose an unsupported ESP transform (" + espId + "/" + au + ")");
        Integer em = a.get(4);
        if (em == null || (em != 4 && em != 61444 && em != 2 && em != 3 && em != 61443)) {
            log.log("IKE: unexpected encapsulation mode " + em);
        }
        log.log("IKE phase 2: ESP " + ce.name + ", " + ca.name);

        // HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)
        byte[] hash3 = prf(skeyidA, new byte[]{0}, be(mid), ni, nr2.body);
        List<P> m3 = new ArrayList<>();
        m3.add(new P(NP_HASH, hash3));
        byte[] lastIn = Arrays.copyOfRange(rct, rct.length - enc.block, rct.length);
        byte[] ct3 = cbc(true, lastIn, pad(payloads(m3), enc.block));
        byte[] msg3 = isakmp(ckyI, ckyR, NP_HASH, EX_QUICK, 1, mid, ct3);
        send(s4500, true, msg3);

        // KEYMAT: prf(SKEYID_d, [Kprev |] protocol | SPI | Ni_b | Nr_b)
        EspSa res = new EspSa();
        res.inSpi = inSpi;
        res.outSpi = outSpi;
        res.enc = ce;
        res.auth = ca;
        int need = ce.keyBytes + ca.len;
        byte[] kin = keymat(need, inSpi, ni, nr2.body);
        byte[] kout = keymat(need, outSpi, ni, nr2.body);
        res.encKeyIn = Arrays.copyOfRange(kin, 0, ce.keyBytes);
        res.authKeyIn = Arrays.copyOfRange(kin, ce.keyBytes, need);
        res.encKeyOut = Arrays.copyOfRange(kout, 0, ce.keyBytes);
        res.authKeyOut = Arrays.copyOfRange(kout, ce.keyBytes, need);
        res.localIp = localIp;
        res.socket = s4500;
        return res;
    }

    private byte[] keymat(int need, int spi, byte[] ni, byte[] nr) throws IOException {
        byte[] seed = concat(new byte[]{3}, be(spi), ni, nr);
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        byte[] prev = new byte[0];
        while (o.size() < need) {
            prev = prf(skeyidD, prev, seed);
            o.write(prev, 0, prev.length);
        }
        return Arrays.copyOf(o.toByteArray(), need);
    }

    /** Length of the payload chain that starts at offset 0 (the rest is CBC padding). */
    private static int endOfChain(byte[] data) {
        int off = 0;
        // the first payload header is part of the chain; walk next pointers until 0
        int next;
        do {
            if (off + 4 > data.length) return data.length;
            next = data[off] & 0xFF;
            int len = r16(data, off + 2);
            if (len < 4) return data.length;
            off += len;
        } while (next != 0 && off < data.length);
        return Math.min(off, data.length);
    }
}
