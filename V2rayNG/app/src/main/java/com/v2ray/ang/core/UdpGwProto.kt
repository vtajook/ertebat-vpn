package com.v2ray.ang.core

import java.io.EOFException
import java.io.InputStream

/**
 * Wire formats of "UDP over an SSH tunnel" through a badvpn-udpgw server on the SSH host.
 *
 * udpgw frame, on a TCP stream: `len` (2 bytes little endian, size of the rest) | `flags` (1) | `conid`
 * (2 bytes little endian) | address (4 or 16 bytes, network order) | port (2 bytes big endian) | data.
 * The same layout is used in both directions; in replies the address/port are the remote the data came from.
 */
object UdpGwProto {
    const val FLAG_KEEPALIVE = 1
    const val FLAG_IPV6 = 8

    class Frame(val flags: Int, val conId: Int, val addr: ByteArray, val port: Int, val data: ByteArray) {
        val isKeepAlive get() = flags and FLAG_KEEPALIVE != 0
    }

    fun encode(conId: Int, addr: ByteArray, port: Int, data: ByteArray, off: Int = 0, len: Int = data.size): ByteArray {
        require(addr.size == 4 || addr.size == 16) { "bad address" }
        val body = 1 + 2 + addr.size + 2 + len
        require(body <= 0xFFFF) { "datagram too large" }
        val out = ByteArray(2 + body)
        out[0] = (body and 0xFF).toByte()
        out[1] = ((body shr 8) and 0xFF).toByte()
        out[2] = (if (addr.size == 16) FLAG_IPV6 else 0).toByte()
        out[3] = (conId and 0xFF).toByte()
        out[4] = ((conId shr 8) and 0xFF).toByte()
        System.arraycopy(addr, 0, out, 5, addr.size)
        val p = 5 + addr.size
        out[p] = ((port shr 8) and 0xFF).toByte()
        out[p + 1] = (port and 0xFF).toByte()
        System.arraycopy(data, off, out, p + 2, len)
        return out
    }

    /** Reads one frame; null at a clean end of the stream. */
    fun read(input: InputStream): Frame? {
        val h0 = input.read()
        if (h0 < 0) return null
        val h1 = input.read()
        if (h1 < 0) throw EOFException()
        val body = h0 or (h1 shl 8)
        val buf = ByteArray(body)
        var off = 0
        while (off < body) {
            val n = input.read(buf, off, body - off)
            if (n < 0) throw EOFException()
            off += n
        }
        if (body < 3) return Frame(0, 0, ByteArray(0), 0, ByteArray(0))
        val flags = buf[0].toInt() and 0xFF
        val conId = (buf[1].toInt() and 0xFF) or ((buf[2].toInt() and 0xFF) shl 8)
        if (flags and FLAG_KEEPALIVE != 0) return Frame(flags, conId, ByteArray(0), 0, ByteArray(0))
        val aLen = if (flags and FLAG_IPV6 != 0) 16 else 4
        if (body < 3 + aLen + 2) return Frame(0, conId, ByteArray(0), 0, ByteArray(0))
        val addr = buf.copyOfRange(3, 3 + aLen)
        val port = ((buf[3 + aLen].toInt() and 0xFF) shl 8) or (buf[4 + aLen].toInt() and 0xFF)
        return Frame(flags, conId, addr, port, buf.copyOfRange(5 + aLen, body))
    }

    /** A datagram of the SOCKS5 UDP relay: destination and payload. */
    class SocksDatagram(val addr: ByteArray?, val host: String?, val port: Int, val data: ByteArray)

    /** Parses `RSV(2) FRAG ATYP ADDR PORT DATA`; null for fragments or malformed packets. */
    fun parseSocksUdp(buf: ByteArray, len: Int): SocksDatagram? {
        if (len < 10 || buf[2].toInt() != 0) return null
        var p = 4
        var addr: ByteArray? = null
        var host: String? = null
        when (buf[3].toInt()) {
            1 -> { addr = buf.copyOfRange(p, p + 4); p += 4 }
            4 -> { if (len < 22) return null; addr = buf.copyOfRange(p, p + 16); p += 16 }
            3 -> {
                val n = buf[p].toInt() and 0xFF
                if (len < p + 1 + n + 2) return null
                host = String(buf, p + 1, n, Charsets.UTF_8)
                p += 1 + n
            }
            else -> return null
        }
        if (len < p + 2) return null
        val port = ((buf[p].toInt() and 0xFF) shl 8) or (buf[p + 1].toInt() and 0xFF)
        return SocksDatagram(addr, host, port, buf.copyOfRange(p + 2, len))
    }

    /** Builds a SOCKS5 UDP relay datagram coming from [addr]:[port]. */
    fun buildSocksUdp(addr: ByteArray, port: Int, data: ByteArray): ByteArray {
        val out = ByteArray(4 + addr.size + 2 + data.size)
        out[3] = (if (addr.size == 16) 4 else 1).toByte()
        System.arraycopy(addr, 0, out, 4, addr.size)
        val p = 4 + addr.size
        out[p] = ((port shr 8) and 0xFF).toByte()
        out[p + 1] = (port and 0xFF).toByte()
        System.arraycopy(data, 0, out, p + 2, data.size)
        return out
    }
}
