package com.v2ray.ang.core.l2tp

import android.net.VpnService
import android.os.ParcelFileDescriptor
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.routing.DirectRoutes
import com.v2ray.ang.util.LogUtil
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * L2TP/IPsec (IKEv1, pre-shared key, NAT-T, ESP in UDP 4500) client, entirely in user space.
 * [run] blocks until the session ends; [stop] can be called from any thread.
 */
class L2tpEngine(
    private val service: VpnService,
    private val remarks: String,
    private val username: String,
    private val password: String,
    private val psk: String,
    private val listener: Listener,
) {
    interface Listener {
        fun onConnected()
        fun onLog(line: String)
    }

    @Volatile var rxBytes = 0L
        private set
    @Volatile var txBytes = 0L
        private set
    /** True when the session ended only because the IPsec SA reached its lifetime; the caller should reconnect. */
    @Volatile var expired = false
        private set

    private val stopped = AtomicBoolean(false)
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var socket: java.net.DatagramSocket? = null
    @Volatile private var ppp: L2tpPpp? = null
    @Volatile private var lastRx = 0L

    fun stop() {
        if (!stopped.compareAndSet(false, true)) return
        runCatching { ppp?.close() }
        runCatching { socket?.close() }
        runCatching { tun?.close() }
    }

    /** @return an error text, or null when the session ended normally. */
    fun run(server: String, @Suppress("UNUSED_PARAMETER") port: Int): String? {
        var error: String? = null
        try {
            val addr = InetAddress.getAllByName(server).firstOrNull { it.address.size == 4 }
                ?: return "Cannot resolve the server address (IPv4)"
            listener.onLog("IKE: negotiating with ${addr.hostAddress}")
            val ike = Ike1(addr, psk.toByteArray(Charsets.UTF_8), { s -> service.protect(s) }, { listener.onLog(it) })
            val sa = try {
                ike.negotiate()
            } catch (e: java.io.IOException) {
                return if (stopped.get()) null else (e.message ?: "IPsec negotiation failed")
            }
            if (stopped.get()) return null
            val sock = sa.socket
            socket = sock
            sock.soTimeout = 2000
            val esp = Esp(sa)

            val sink = object : L2tpPpp.Sink {
                override fun ipPacket(packet: ByteArray) {
                    val out = tunOut ?: return
                    try {
                        out.write(packet)
                        rxBytes += packet.size
                    } catch (_: Exception) {
                    }
                }

                override fun log(line: String) = listener.onLog(line)
            }
            val tx = L2tpPpp.Tx { msg -> sendInner(esp, sock, msg) }
            val p = L2tpPpp(tx, sink, username, password)
            ppp = p
            lastRx = System.currentTimeMillis()

            val rx = Thread({ receiveLoop(esp, sock, p) }, "l2tp-rx").also { it.isDaemon = true; it.start() }
            val link = try {
                p.connect()
            } catch (e: java.io.IOException) {
                return if (stopped.get()) null else (e.message ?: "L2TP failed")
            }
            if (stopped.get()) return null

            val pfd = establishTun(link) ?: return "Could not create the VPN interface"
            tun = pfd
            val input = FileInputStream(pfd.fileDescriptor)
            tunOut = FileOutputStream(pfd.fileDescriptor)
            val startedAt = System.currentTimeMillis()
            listener.onConnected()

            val tunThread = Thread({
                val buf = ByteArray(2048)
                try {
                    while (!stopped.get()) {
                        val n = input.read(buf)
                        if (n <= 0) continue
                        if ((buf[0].toInt() shr 4) != 4) continue // IPv4 only
                        p.sendIp(buf, n)
                        txBytes += n
                    }
                } catch (_: Exception) {
                }
            }, "l2tp-tun").also { it.isDaemon = true; it.start() }

            var tick = 0
            while (!stopped.get()) {
                try {
                    Thread.sleep(1000)
                } catch (_: InterruptedException) {
                    break
                }
                tick++
                p.tick(tick % 20 == 0)
                if (tick % 20 == 0) runCatching { sock.send(DatagramPacket(byteArrayOf(0xFF.toByte()), 1)) }
                val f = p.failure()
                if (f != null) { error = f; break }
                if (p.isClosed) { error = "The server closed the session"; break }
                val now = System.currentTimeMillis()
                if (now - lastRx > 90_000) { error = "The server stopped answering"; break }
                if (now - startedAt > SA_LIFETIME_MS) { expired = true; break }
            }
            stop()
            runCatching { tunThread.interrupt(); rx.interrupt() }
        } catch (t: Throwable) {
            LogUtil.e(AppConfig.TAG, "L2TP engine crashed", t)
            error = t.message ?: t.javaClass.simpleName
        } finally {
            stop()
            tunOut = null
        }
        return if (stopped.get() && !expired && error == null) null else error
    }

    @Volatile private var tunOut: FileOutputStream? = null

    private fun sendInner(esp: Esp, sock: java.net.DatagramSocket, msg: ByteArray) {
        val inner = ByteArray(8 + msg.size)
        inner[0] = 0x06; inner[1] = 0xA5.toByte() // 1701
        inner[2] = 0x06; inner[3] = 0xA5.toByte()
        val len = 8 + msg.size
        inner[4] = (len shr 8).toByte(); inner[5] = len.toByte()
        System.arraycopy(msg, 0, inner, 8, msg.size)
        val pkt = esp.encrypt(inner, 17)
        sock.send(DatagramPacket(pkt, pkt.size))
    }

    private fun receiveLoop(esp: Esp, sock: java.net.DatagramSocket, p: L2tpPpp) {
        val buf = ByteArray(4096)
        val dp = DatagramPacket(buf, buf.size)
        val next = IntArray(1)
        while (!stopped.get()) {
            try {
                dp.length = buf.size
                sock.receive(dp)
                if (dp.length < 9) continue
                val inner = esp.decrypt(buf, dp.length, next) ?: continue
                lastRx = System.currentTimeMillis()
                if (next[0] != 17 || inner.size < 8) continue
                p.onL2tp(inner.copyOfRange(8, inner.size), inner.size - 8)
            } catch (_: SocketTimeoutException) {
            } catch (e: Exception) {
                if (stopped.get()) return
                LogUtil.w(AppConfig.TAG, "L2TP rx: ${e.message}")
                if (sock.isClosed) return
            }
        }
    }

    private fun establishTun(link: L2tpPpp.Link): ParcelFileDescriptor? {
        val b = service.Builder().setBlocking(true).setSession(remarks.ifBlank { AppConfig.TAG })
        val routes = DirectRoutes.Collector(b, runCatching { DirectRoutes.directRanges(service) }.getOrDefault(emptyList()))
        return try {
            b.setMtu(if (link.mru in 1000..1360) link.mru else 1360)
            b.addAddress(L2tpPpp.ip(link.ip), 32)
            var dns = 0
            for (d in listOf(link.dns1, link.dns2)) {
                if (!L2tpPpp.isZero(d)) runCatching {
                    val s = L2tpPpp.ip(d)
                    b.addDnsServer(s); routes.pin(s); dns++
                }
            }
            if (dns == 0) {
                b.addDnsServer("1.1.1.1")
                b.addDnsServer("8.8.8.8")
            }
            routes.addRoute("0.0.0.0", 0)
            routes.apply()
            b.establish()
        } catch (t: Throwable) {
            LogUtil.e(AppConfig.TAG, "L2TP tun setup failed", t)
            null
        }
    }

    companion object {
        /** Phase 2 lifetime is 3600 s; reconnect a bit earlier. */
        private const val SA_LIFETIME_MS = 3_300_000L
    }
}
