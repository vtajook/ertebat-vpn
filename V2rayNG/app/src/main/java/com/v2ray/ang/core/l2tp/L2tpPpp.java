package com.v2ray.ang.core.l2tp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

/**
 * L2TP (RFC 2661) control and data channel plus the PPP negotiation on top of it (LCP, PAP / CHAP / MS-CHAPv2,
 * IPCP). It is transport independent: datagrams go out through [Tx] and come in through [onL2tp]. IPv4 only.
 */
final class L2tpPpp {

    interface Tx {
        /** Sends one L2TP message (the payload of the UDP 1701 datagram). */
        void send(byte[] l2tpMessage) throws IOException;
    }

    interface Sink {
        /** An IPv4 packet that came out of the tunnel. */
        void ipPacket(byte[] packet);

        void log(String line);
    }

    /** Parameters learned from the server once the link is up. */
    static final class Link {
        byte[] ip = new byte[4];
        byte[] dns1 = new byte[4];
        byte[] dns2 = new byte[4];
        byte[] peerIp = new byte[4];
        int mru = 1400;
    }

    private static final int PPP_LCP = 0xC021, PPP_PAP = 0xC023, PPP_CHAP = 0xC223, PPP_IPCP = 0x8021,
            PPP_IP = 0x0021;

    private final Tx tx;
    private final Sink sink;
    private final String user, pass;
    private final SecureRandom rnd = new SecureRandom();
    private final Object lock = new Object();

    // L2TP state
    private final int myTid = 1 + new SecureRandom().nextInt(0xFFFE);
    private final int mySid = 1 + new SecureRandom().nextInt(0xFFFE);
    private int peerTid, peerSid;
    private int ns = 0, nr = 0;
    private boolean tunnelUp, sessionUp;
    private static final class Pending {
        int ns;
        byte[] avps;
        int sid;
        int sent;
        long last;
    }
    private final List<Pending> pending = new ArrayList<>();

    // PPP state
    private int lcpId = 0, ipcpId = 0, protoRejId = 0;
    private final int myMagic = new SecureRandom().nextInt();
    private int myMru = 1400;
    private boolean lcpSentReq, lcpLocalAcked, lcpRemoteAcked, lcpOpen;
    private int authProto = 0; // what the server wants from us: PPP_PAP / PPP_CHAP / 0
    private int chapAlg = 0;
    private boolean authDone, authSent;
    private boolean ipcpStarted, ipcpLocalAcked, ipcpRemoteAcked, ipcpOpen;
    private boolean wantDns1 = true, wantDns2 = true;
    private final Link link = new Link();
    private String failure;
    private boolean closed;
    private long lastLcpSend, lastIpcpSend;
    private int lcpTries, ipcpTries;
    private byte[] lastLcpReq, lastIpcpReq;

    L2tpPpp(Tx tx, Sink sink, String user, String pass) {
        this.tx = tx;
        this.sink = sink;
        this.user = user == null ? "" : user;
        this.pass = pass == null ? "" : pass;
    }

    // ── public API ─────────────────────────────────────────────────────────────────────────────

    /** Brings the tunnel, the session and the PPP link up; blocks (up to ~45 s). */
    Link connect() throws IOException {
        synchronized (lock) {
            ByteArrayOutputStream a = new ByteArrayOutputStream();
            avp(a, 0, new byte[]{0, 1}); // SCCRQ
            avp(a, 2, new byte[]{1, 0}); // protocol version 1.0
            avp(a, 3, new byte[]{0, 0, 0, 3}); // framing: async + sync
            avp(a, 7, "EGN".getBytes(StandardCharsets.US_ASCII));
            avp(a, 9, new byte[]{(byte) (myTid >> 8), (byte) myTid});
            queueControl(a.toByteArray(), 0, true);
            waitFor(15000, () -> tunnelUp, "L2TP tunnel");

            a = new ByteArrayOutputStream();
            avp(a, 0, new byte[]{0, 10}); // ICRQ
            avp(a, 14, new byte[]{(byte) (mySid >> 8), (byte) mySid});
            byte[] serial = new byte[4];
            rnd.nextBytes(serial);
            avp(a, 15, serial);
            queueControl(a.toByteArray(), 0, false);
            waitFor(15000, () -> sessionUp, "L2TP session");

            startLcp();
            waitFor(45000, () -> ipcpOpen, "PPP negotiation");
            sink.log("PPP up: " + ip(link.ip) + " dns " + ip(link.dns1) + " " + ip(link.dns2));
            return link;
        }
    }

    /** Called about once per second while the link is up (keepalives, retransmissions). */
    void tick(boolean sendEcho) {
        synchronized (lock) {
            try {
                retransmit();
                if (sendEcho && ipcpOpen) {
                    byte[] data = new byte[4];
                    putInt(data, 0, myMagic);
                    sendLcp(9, ++lcpId, data);
                }
            } catch (IOException ignored) {
            }
        }
    }

    String failure() {
        synchronized (lock) {
            return failure;
        }
    }

    boolean isClosed() {
        synchronized (lock) {
            return closed;
        }
    }

    void sendIp(byte[] packet, int len) throws IOException {
        byte[] frame = new byte[4 + len];
        frame[0] = (byte) 0xFF;
        frame[1] = 0x03;
        frame[2] = 0x00;
        frame[3] = 0x21;
        System.arraycopy(packet, 0, frame, 4, len);
        sendData(frame);
    }

    /** Ends the session politely (best effort). */
    void close() {
        synchronized (lock) {
            if (closed) return;
            try {
                if (ipcpOpen || lcpOpen) sendLcp(5, ++lcpId, new byte[0]);
                if (sessionUp) {
                    ByteArrayOutputStream a = new ByteArrayOutputStream();
                    avp(a, 0, new byte[]{0, 14}); // CDN
                    avp(a, 1, new byte[]{0, 1, 0, 0}); // result: call disconnected
                    avp(a, 14, new byte[]{(byte) (mySid >> 8), (byte) mySid});
                    sendControlNow(a.toByteArray(), peerSid);
                }
                if (tunnelUp) {
                    ByteArrayOutputStream a = new ByteArrayOutputStream();
                    avp(a, 0, new byte[]{0, 4}); // StopCCN
                    avp(a, 1, new byte[]{0, 1, 0, 0});
                    avp(a, 9, new byte[]{(byte) (myTid >> 8), (byte) myTid});
                    sendControlNow(a.toByteArray(), 0);
                }
            } catch (IOException ignored) {
            }
            closed = true;
            lock.notifyAll();
        }
    }

    // ── waiting helper ─────────────────────────────────────────────────────────────────────────

    private interface Cond {
        boolean ok();
    }

    private void waitFor(long timeoutMs, Cond cond, String what) throws IOException {
        long end = System.currentTimeMillis() + timeoutMs;
        while (!cond.ok()) {
            if (failure != null) throw new IOException(failure);
            if (closed) throw new IOException("The server closed the session");
            long left = end - System.currentTimeMillis();
            if (left <= 0) throw new IOException("Timeout during " + what + " (the server did not answer)");
            try {
                lock.wait(Math.min(left, 500));
            } catch (InterruptedException e) {
                throw new IOException("Interrupted");
            }
            retransmit();
        }
    }

    // ── L2TP ───────────────────────────────────────────────────────────────────────────────────

    private static void avp(ByteArrayOutputStream o, int type, byte[] value) {
        int len = 6 + value.length;
        o.write(0x80 | (len >> 8));
        o.write(len);
        o.write(0);
        o.write(0);
        o.write(type >> 8);
        o.write(type);
        o.write(value, 0, value.length);
    }

    private void queueControl(byte[] avps, int sid, boolean tunnelMsg) throws IOException {
        Pending p = new Pending();
        p.ns = ns++ & 0xFFFF;
        p.avps = avps;
        p.sid = sid;
        pending.add(p);
        transmit(p);
    }

    private void transmit(Pending p) throws IOException {
        p.sent++;
        p.last = System.currentTimeMillis();
        tx.send(controlPacket(peerTid, p.sid, p.ns, nr, p.avps));
    }

    private void sendControlNow(byte[] avps, int sid) throws IOException {
        Pending p = new Pending();
        p.ns = ns++ & 0xFFFF;
        p.avps = avps;
        p.sid = sid;
        tx.send(controlPacket(sid == 0 && !sessionUp ? peerTid : peerTid, sid, p.ns, nr, avps));
    }

    private static byte[] controlPacket(int tid, int sid, int ns, int nr, byte[] avps) {
        int len = 12 + avps.length;
        byte[] b = new byte[len];
        b[0] = (byte) 0xC8;
        b[1] = 0x02;
        b[2] = (byte) (len >> 8);
        b[3] = (byte) len;
        b[4] = (byte) (tid >> 8);
        b[5] = (byte) tid;
        b[6] = (byte) (sid >> 8);
        b[7] = (byte) sid;
        b[8] = (byte) (ns >> 8);
        b[9] = (byte) ns;
        b[10] = (byte) (nr >> 8);
        b[11] = (byte) nr;
        System.arraycopy(avps, 0, b, 12, avps.length);
        return b;
    }

    private void retransmit() throws IOException {
        long now = System.currentTimeMillis();
        for (Pending p : pending) {
            if (now - p.last >= 2000) {
                if (p.sent >= 8) {
                    failure = "The L2TP server stopped answering";
                    lock.notifyAll();
                    return;
                }
                transmit(p);
            }
        }
        if (lcpSentReq && !lcpOpen && lastLcpReq != null && now - lastLcpSend >= 3000 && !(lcpLocalAcked)) {
            if (++lcpTries > 10) {
                failure = "PPP: the server did not answer the link negotiation";
                lock.notifyAll();
                return;
            }
            lastLcpSend = now;
            sendPpp(PPP_LCP, lastLcpReq);
        }
        if (ipcpStarted && !ipcpOpen && lastIpcpReq != null && now - lastIpcpSend >= 3000 && !ipcpLocalAcked) {
            if (++ipcpTries > 10) {
                failure = "PPP: the server did not answer the address negotiation";
                lock.notifyAll();
                return;
            }
            lastIpcpSend = now;
            sendPpp(PPP_IPCP, lastIpcpReq);
        }
    }

    /** Entry point for every datagram that arrives on UDP 1701. */
    void onL2tp(byte[] b, int len) {
        synchronized (lock) {
            try {
                handleL2tp(b, len);
            } catch (IOException e) {
                failure = "L2TP: " + e;
                lock.notifyAll();
            } catch (RuntimeException e) {
                sink.log("L2TP: bad packet (" + e + ")");
            }
        }
    }

    private void handleL2tp(byte[] b, int len) throws IOException {
        if (len < 6) return;
        int flags = r16(b, 0);
        if ((flags & 0x000F) != 2) return; // version 2 only
        boolean control = (flags & 0x8000) != 0;
        int off = 2;
        int msgLen = len;
        if ((flags & 0x4000) != 0) {
            msgLen = Math.min(r16(b, off), len);
            off += 2;
        }
        int tid = r16(b, off);
        int sid = r16(b, off + 2);
        off += 4;
        int pns = 0, pnr = 0;
        boolean hasSeq = (flags & 0x0800) != 0;
        if (hasSeq) {
            pns = r16(b, off);
            pnr = r16(b, off + 2);
            off += 4;
        }
        if ((flags & 0x0200) != 0) {
            off += 2 + r16(b, off);
        }
        if (!control) {
            if (off <= msgLen) handlePpp(b, off, msgLen - off);
            return;
        }
        // control message: acknowledge handling
        Iterator<Pending> it = pending.iterator();
        while (it.hasNext()) {
            Pending p = it.next();
            if (((pnr - p.ns) & 0xFFFF) != 0 && ((pnr - p.ns) & 0xFFFF) < 0x8000) it.remove();
        }
        if (off >= msgLen) return; // ZLB: just an acknowledgement
        if (pns != nr) {
            if (((nr - pns) & 0xFFFF) < 0x8000) sendZlb(); // duplicate
            return;
        }
        nr = (nr + 1) & 0xFFFF;
        int msgType = -1;
        int assigned = 0;
        int pos = off;
        byte[] resultCode = null;
        while (pos + 6 <= msgLen) {
            int al = r16(b, pos) & 0x03FF;
            if (al < 6 || pos + al > msgLen) break;
            int vendor = r16(b, pos + 2);
            int type = r16(b, pos + 4);
            if (vendor == 0) {
                if (type == 0 && al >= 8) msgType = r16(b, pos + 6);
                else if ((type == 9 || type == 14) && al >= 8) assigned = r16(b, pos + 6);
                else if (type == 1) resultCode = Arrays.copyOfRange(b, pos + 6, pos + al);
            }
            pos += al;
        }
        switch (msgType) {
            case 2: // SCCRP
                peerTid = assigned;
                tunnelUp = true;
                queueControl(avpMsg(3), 0, true); // SCCCN
                break;
            case 11: // ICRP
                peerSid = assigned;
                sessionUp = true;
                ByteArrayOutputStream a = new ByteArrayOutputStream();
                avp(a, 0, new byte[]{0, 12});
                avp(a, 24, new byte[]{0x05, (byte) 0xF5, (byte) 0xE1, 0x00}); // TX speed 100 Mbit/s
                avp(a, 19, new byte[]{0, 0, 0, 1}); // framing: synchronous
                queueControl(a.toByteArray(), peerSid, false);
                break;
            case 4: // StopCCN
                failure = "The L2TP server closed the tunnel" + describe(resultCode);
                break;
            case 14: // CDN
                failure = "The L2TP server closed the session" + describe(resultCode);
                break;
            case 6: // Hello
                sendZlb();
                break;
            default:
                sendZlb();
        }
        lock.notifyAll();
    }

    private static String describe(byte[] r) {
        if (r == null || r.length < 4) return "";
        return " (result " + r16(r, 0) + ", error " + r16(r, 2) + ")";
    }

    private static byte[] avpMsg(int type) {
        ByteArrayOutputStream a = new ByteArrayOutputStream();
        avp(a, 0, new byte[]{0, (byte) type});
        return a.toByteArray();
    }

    private void sendZlb() throws IOException {
        tx.send(controlPacket(peerTid, 0, ns, nr, new byte[0]));
    }

    private void sendData(byte[] ppp) throws IOException {
        byte[] b = new byte[6 + ppp.length];
        b[0] = 0x00;
        b[1] = 0x02;
        b[2] = (byte) (peerTid >> 8);
        b[3] = (byte) peerTid;
        b[4] = (byte) (peerSid >> 8);
        b[5] = (byte) peerSid;
        System.arraycopy(ppp, 0, b, 6, ppp.length);
        tx.send(b);
    }

    // ── PPP ────────────────────────────────────────────────────────────────────────────────────

    private void sendPpp(int proto, byte[] packet) {
        byte[] frame = new byte[4 + packet.length];
        frame[0] = (byte) 0xFF;
        frame[1] = 0x03;
        frame[2] = (byte) (proto >> 8);
        frame[3] = (byte) proto;
        System.arraycopy(packet, 0, frame, 4, packet.length);
        try {
            sendData(frame);
        } catch (IOException e) {
            sink.log("L2TP send failed: " + e.getMessage());
        }
    }

    private void sendLcpLike(int proto, int code, int id, byte[] data) {
        byte[] p = new byte[4 + data.length];
        p[0] = (byte) code;
        p[1] = (byte) id;
        p[2] = (byte) ((4 + data.length) >> 8);
        p[3] = (byte) (4 + data.length);
        System.arraycopy(data, 0, p, 4, data.length);
        sendPpp(proto, p);
    }

    private void sendLcp(int code, int id, byte[] data) {
        sendLcpLike(PPP_LCP, code, id, data);
    }

    private void handlePpp(byte[] b, int off, int len) {
        if (len < 2) return;
        if ((b[off] & 0xFF) == 0xFF && len >= 4 && b[off + 1] == 0x03) {
            off += 2;
            len -= 2;
        }
        int proto;
        if ((b[off] & 0x01) != 0) { // protocol field compression
            proto = b[off] & 0xFF;
            off += 1;
            len -= 1;
        } else {
            proto = r16(b, off);
            off += 2;
            len -= 2;
        }
        byte[] data = Arrays.copyOfRange(b, off, off + len);
        switch (proto) {
            case PPP_IP:
                if (ipcpOpen) sink.ipPacket(data);
                break;
            case PPP_LCP:
                handleLcp(data);
                break;
            case PPP_PAP:
                handlePap(data);
                break;
            case PPP_CHAP:
                handleChap(data);
                break;
            case PPP_IPCP:
                handleIpcp(data);
                break;
            case 0x80FD: // CCP: no compression / encryption
                if (data.length >= 4 && data[0] == 1) {
                    sendLcpLike(0x80FD, 4, data[1] & 0xFF, Arrays.copyOfRange(data, 4, data.length));
                }
                break;
            default:
                if (proto >= 0xC000 || proto >= 0x8000) {
                    byte[] rej = new byte[2 + data.length];
                    rej[0] = (byte) (proto >> 8);
                    rej[1] = (byte) proto;
                    System.arraycopy(data, 0, rej, 2, data.length);
                    sendLcp(8, ++protoRejId, rej);
                }
        }
    }

    // LCP

    private byte[] lcpRequest() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(1);
        o.write(4);
        o.write(myMru >> 8);
        o.write(myMru);
        o.write(5);
        o.write(6);
        byte[] m = new byte[4];
        putInt(m, 0, myMagic);
        o.write(m, 0, 4);
        return o.toByteArray();
    }

    private void startLcp() {
        lcpSentReq = true;
        lcpId++;
        lastLcpReq = packet(1, lcpId, lcpRequest());
        lastLcpSend = System.currentTimeMillis();
        sendPpp(PPP_LCP, lastLcpReq);
    }

    private static byte[] packet(int code, int id, byte[] data) {
        byte[] p = new byte[4 + data.length];
        p[0] = (byte) code;
        p[1] = (byte) id;
        p[2] = (byte) ((4 + data.length) >> 8);
        p[3] = (byte) (4 + data.length);
        System.arraycopy(data, 0, p, 4, data.length);
        return p;
    }

    private void handleLcp(byte[] d) {
        if (d.length < 4) return;
        int code = d[0] & 0xFF, id = d[1] & 0xFF;
        int len = Math.min(r16(d, 2), d.length);
        byte[] opts = Arrays.copyOfRange(d, 4, len);
        switch (code) {
            case 1: { // Configure-Request from the server
                ByteArrayOutputStream rej = new ByteArrayOutputStream();
                ByteArrayOutputStream nak = new ByteArrayOutputStream();
                int newAuth = 0, newAlg = 0;
                int pos = 0;
                while (pos + 2 <= opts.length) {
                    int t = opts[pos] & 0xFF, l = opts[pos + 1] & 0xFF;
                    if (l < 2 || pos + l > opts.length) break;
                    byte[] o = Arrays.copyOfRange(opts, pos, pos + l);
                    switch (t) {
                        case 1: // MRU
                            if (l == 4) link.mru = Math.min(r16(o, 2), 1500);
                            break;
                        case 2: // ACCM
                        case 5: // magic number
                            break;
                        case 3: // authentication protocol
                            int ap = l >= 4 ? r16(o, 2) : 0;
                            if (ap == PPP_PAP) {
                                newAuth = PPP_PAP;
                            } else if (ap == PPP_CHAP && l >= 5 && ((o[4] & 0xFF) == 5 || (o[4] & 0xFF) == 0x81)) {
                                newAuth = PPP_CHAP;
                                newAlg = o[4] & 0xFF;
                            } else {
                                // ask for MS-CHAPv2 instead (EAP, MS-CHAPv1, ... are not supported)
                                nak.write(new byte[]{3, 5, (byte) 0xC2, 0x23, (byte) 0x81}, 0, 5);
                            }
                            break;
                        default: // PFC, ACFC, callback, ...
                            rej.write(o, 0, o.length);
                    }
                    pos += l;
                }
                if (rej.size() > 0) {
                    sendLcp(4, id, rej.toByteArray());
                } else if (nak.size() > 0) {
                    sendLcp(3, id, nak.toByteArray());
                } else {
                    authProto = newAuth;
                    chapAlg = newAlg;
                    sendLcp(2, id, opts);
                    lcpRemoteAcked = true;
                    maybeLcpOpen();
                }
                break;
            }
            case 2: // Configure-Ack
                if (id == lcpId) {
                    lcpLocalAcked = true;
                    maybeLcpOpen();
                }
                break;
            case 3: { // Configure-Nak: adopt a changed MRU
                int pos = 0;
                while (pos + 2 <= opts.length) {
                    int t = opts[pos] & 0xFF, l = opts[pos + 1] & 0xFF;
                    if (l < 2 || pos + l > opts.length) break;
                    if (t == 1 && l == 4) myMru = r16(opts, pos + 2);
                    pos += l;
                }
                resendLcp();
                break;
            }
            case 4: // Configure-Reject: drop what was rejected (only MRU is optional)
                myMru = 1500;
                resendLcp();
                break;
            case 5: // Terminate-Request
                sendLcp(6, id, new byte[0]);
                failure = "The server ended the PPP session";
                lock.notifyAll();
                break;
            case 9: { // Echo-Request
                byte[] data = new byte[Math.max(4, opts.length)];
                System.arraycopy(opts, 0, data, 0, opts.length);
                putInt(data, 0, myMagic);
                sendLcp(10, id, data);
                break;
            }
            default:
                break;
        }
    }

    private void resendLcp() {
        lcpId++;
        lastLcpReq = packet(1, lcpId, lcpRequest());
        lastLcpSend = System.currentTimeMillis();
        sendPpp(PPP_LCP, lastLcpReq);
    }

    private void maybeLcpOpen() {
        if (lcpOpen || !lcpLocalAcked || !lcpRemoteAcked) return;
        lcpOpen = true;
        sink.log("PPP LCP open, authentication: " + (authProto == PPP_PAP ? "PAP" : authProto == PPP_CHAP ? (chapAlg == 0x81 ? "MS-CHAPv2" : "CHAP") : "none"));
        if (authProto == PPP_PAP) {
            ByteArrayOutputStream o = new ByteArrayOutputStream();
            byte[] u = user.getBytes(StandardCharsets.UTF_8), p = pass.getBytes(StandardCharsets.UTF_8);
            o.write(u.length);
            o.write(u, 0, u.length);
            o.write(p.length);
            o.write(p, 0, p.length);
            sendLcpLike(PPP_PAP, 1, 1, o.toByteArray());
            authSent = true;
        } else if (authProto == 0) {
            authDone = true;
            startIpcp();
        }
        // CHAP: wait for the server's challenge
    }

    private void handlePap(byte[] d) {
        if (d.length < 4) return;
        if (d[0] == 2) {
            authDone = true;
            startIpcp();
        } else if (d[0] == 3) {
            failure = "Authentication failed (wrong user name or password)";
            lock.notifyAll();
        }
    }

    private void handleChap(byte[] d) {
        if (d.length < 4) return;
        int code = d[0] & 0xFF, id = d[1] & 0xFF;
        int len = Math.min(r16(d, 2), d.length);
        try {
            if (code == 1 && len > 5) { // Challenge
                int vs = d[4] & 0xFF;
                byte[] challenge = Arrays.copyOfRange(d, 5, 5 + vs);
                byte[] name = user.getBytes(StandardCharsets.UTF_8);
                ByteArrayOutputStream o = new ByteArrayOutputStream();
                if (chapAlg == 0x81) {
                    byte[] peer = new byte[16];
                    rnd.nextBytes(peer);
                    byte[] nt = MsChap.ntResponse(challenge, peer, user, pass);
                    o.write(49);
                    o.write(peer, 0, 16);
                    o.write(new byte[8], 0, 8);
                    o.write(nt, 0, 24);
                    o.write(0);
                } else {
                    byte[] r = MsChap.chapMd5(id, pass.getBytes(StandardCharsets.UTF_8), challenge);
                    o.write(r.length);
                    o.write(r, 0, r.length);
                }
                o.write(name, 0, name.length);
                sendLcpLike(PPP_CHAP, 2, id, o.toByteArray());
                authSent = true;
            } else if (code == 3) { // Success
                authDone = true;
                startIpcp();
            } else if (code == 4) {
                failure = "Authentication failed (wrong user name or password)";
                lock.notifyAll();
            }
        } catch (Exception e) {
            failure = "CHAP: " + e;
            lock.notifyAll();
        }
    }

    // IPCP

    private byte[] ipcpRequest() {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(3);
        o.write(6);
        o.write(link.ip, 0, 4);
        if (wantDns1) {
            o.write(129);
            o.write(6);
            o.write(link.dns1, 0, 4);
        }
        if (wantDns2) {
            o.write(131);
            o.write(6);
            o.write(link.dns2, 0, 4);
        }
        return o.toByteArray();
    }

    private void startIpcp() {
        if (ipcpStarted) return;
        ipcpStarted = true;
        resendIpcp();
    }

    private void resendIpcp() {
        ipcpId++;
        lastIpcpReq = packet(1, ipcpId, ipcpRequest());
        lastIpcpSend = System.currentTimeMillis();
        ipcpLocalAcked = false;
        sendPpp(PPP_IPCP, lastIpcpReq);
    }

    private void handleIpcp(byte[] d) {
        if (d.length < 4) return;
        int code = d[0] & 0xFF, id = d[1] & 0xFF;
        int len = Math.min(r16(d, 2), d.length);
        byte[] opts = Arrays.copyOfRange(d, 4, len);
        switch (code) {
            case 1: { // server's Configure-Request: its own address, maybe more
                ByteArrayOutputStream rej = new ByteArrayOutputStream();
                int pos = 0;
                while (pos + 2 <= opts.length) {
                    int t = opts[pos] & 0xFF, l = opts[pos + 1] & 0xFF;
                    if (l < 2 || pos + l > opts.length) break;
                    if (t == 3 && l == 6) System.arraycopy(opts, pos + 2, link.peerIp, 0, 4);
                    else if (t != 3) rej.write(opts, pos, l);
                    pos += l;
                }
                if (rej.size() > 0) {
                    sendLcpLike(PPP_IPCP, 4, id, rej.toByteArray());
                } else {
                    sendLcpLike(PPP_IPCP, 2, id, opts);
                    ipcpRemoteAcked = true;
                    maybeIpcpOpen();
                }
                break;
            }
            case 2:
                if (id == ipcpId) {
                    ipcpLocalAcked = true;
                    maybeIpcpOpen();
                }
                break;
            case 3: { // Nak: the server tells which address / DNS to use
                int pos = 0;
                while (pos + 2 <= opts.length) {
                    int t = opts[pos] & 0xFF, l = opts[pos + 1] & 0xFF;
                    if (l < 2 || pos + l > opts.length) break;
                    if (l == 6) {
                        if (t == 3) System.arraycopy(opts, pos + 2, link.ip, 0, 4);
                        else if (t == 129) System.arraycopy(opts, pos + 2, link.dns1, 0, 4);
                        else if (t == 131) System.arraycopy(opts, pos + 2, link.dns2, 0, 4);
                    }
                    pos += l;
                }
                resendIpcp();
                break;
            }
            case 4: { // Reject: the server does not hand out DNS
                int pos = 0;
                while (pos + 2 <= opts.length) {
                    int t = opts[pos] & 0xFF, l = opts[pos + 1] & 0xFF;
                    if (l < 2) break;
                    if (t == 129) wantDns1 = false;
                    if (t == 131) wantDns2 = false;
                    pos += l;
                }
                resendIpcp();
                break;
            }
            default:
                break;
        }
    }

    private void maybeIpcpOpen() {
        if (ipcpOpen || !ipcpLocalAcked || !ipcpRemoteAcked) return;
        if (isZero(link.ip)) return; // nothing assigned yet
        ipcpOpen = true;
        lock.notifyAll();
    }

    // ── small helpers ──────────────────────────────────────────────────────────────────────────

    static boolean isZero(byte[] b) {
        for (byte x : b) if (x != 0) return false;
        return true;
    }

    static String ip(byte[] b) {
        return (b[0] & 0xFF) + "." + (b[1] & 0xFF) + "." + (b[2] & 0xFF) + "." + (b[3] & 0xFF);
    }

    private static int r16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }

    private static void putInt(byte[] b, int off, int v) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }
}
