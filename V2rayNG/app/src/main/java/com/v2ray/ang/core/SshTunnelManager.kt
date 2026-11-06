package com.v2ray.ang.core

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.util.LogUtil
import net.schmizz.keepalive.KeepAliveProvider
import net.schmizz.sshj.DefaultConfig
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.EOFException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.SocketFactory
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.Security
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * Carries an SSH profile through the normal core pipeline.
 *
 * The app logs in to the SSH server with sshj and exposes a local SOCKS5 proxy on 127.0.0.1. Every
 * SOCKS CONNECT becomes an SSH `direct-tcpip` channel (like `ssh -D`). The core is then started with
 * a plain SOCKS outbound that points at this proxy (see CoreOutboundBuilder.toOutboundSsh), so
 * routing, the TUN bridge, per-app proxy and the speed/traffic stats work exactly like for any other
 * profile.
 *
 * Notes:
 *  - TCP only. SSH cannot carry UDP, so UDP associate is refused and apps fall back to TCP.
 *  - The server must allow TCP forwarding (`AllowTcpForwarding yes`).
 *  - The app process is excluded from the VPN (see CoreVpnService.configurePerAppProxy), so the
 *    SSH socket itself never loops back into the tunnel.
 *  - Never call [start]/[stop] expecting network I/O on the calling thread: [start] only binds the
 *    local port and returns, the SSH login runs on a worker thread, and [stop] tears down in the
 *    background. This matters because the services call into the core manager on the main thread.
 */
object SshTunnelManager {

    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val HANDSHAKE_TIMEOUT_MS = 10_000
    private const val KEEPALIVE_SECONDS = 15
    private const val BUFFER_SIZE = 16 * 1024

    private val connLock = Any()

    @Volatile
    private var generation = 0

    @Volatile
    private var profile: ProfileItem? = null

    @Volatile
    private var client: SSHClient? = null

    @Volatile
    private var connecting: SSHClient? = null

    @Volatile
    private var server: ServerSocket? = null

    @Volatile
    private var pool: ExecutorService? = null

    /** Port of the local SOCKS5 proxy, 0 when no SSH tunnel is active. */
    @Volatile
    var localPort: Int = 0
        private set

    /**
     * Starts the local SOCKS5 proxy for [config] and logs in to the SSH server in the background.
     *
     * @param onFatal called once (on a worker thread) when the initial SSH login fails, with a short
     *                human readable reason. Later drops are healed by reconnecting on demand.
     * @return the local SOCKS5 port, ready to be used right away.
     */
    @Synchronized
    @Throws(IOException::class)
    fun start(config: ProfileItem, onFatal: (String) -> Unit): Int {
        stopInternal()
        installBouncyCastle()

        val gen = ++generation
        profile = config

        val ss = ServerSocket(0, 128, InetAddress.getByName(AppConfig.LOOPBACK))
        val executor = Executors.newCachedThreadPool { r ->
            Thread(r, "ssh-tunnel").apply { isDaemon = true }
        }
        server = ss
        pool = executor
        localPort = ss.localPort

        executor.execute { acceptLoop(ss, executor, gen) }
        executor.execute {
            try {
                ensureConnected(gen)
                LogUtil.i(AppConfig.TAG, "SSH tunnel up on 127.0.0.1:${ss.localPort}")
            } catch (e: Exception) {
                if (gen == generation) {
                    val message = describe(e)
                    LogUtil.e(AppConfig.TAG, "SSH login failed: $message", e)
                    onFatal(message)
                }
            }
        }
        return ss.localPort
    }

    /** Stops the tunnel. Safe to call from any thread, including the main thread. */
    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        generation++
        val oldServer = server
        val oldPool = pool
        val oldClient = client
        val oldConnecting = connecting
        server = null
        pool = null
        client = null
        connecting = null
        profile = null
        localPort = 0

        if (oldServer == null && oldPool == null && oldClient == null && oldConnecting == null) return

        // Closing sockets and sending the SSH disconnect is network I/O: never on the caller's thread.
        Thread({
            runCatching { oldServer?.close() }
            runCatching { oldPool?.shutdownNow() }
            runCatching { oldConnecting?.disconnect() }
            runCatching { oldClient?.disconnect() }
        }, "ssh-tunnel-stop").apply { isDaemon = true }.start()
    }

    // ── SSH session ────────────────────────────────────────────────────────────────────────────

    private fun installBouncyCastle() {
        // Android ships a stripped-down "BC" provider; sshj needs the full BouncyCastle one.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    private fun isUsable(c: SSHClient?): Boolean = c != null && c.isConnected && c.isAuthenticated

    @Throws(IOException::class)
    private fun ensureConnected(gen: Int): SSHClient {
        client?.takeIf { isUsable(it) }?.let { return it }

        synchronized(connLock) {
            client?.takeIf { isUsable(it) }?.let { return it }
            if (gen != generation) throw IOException("SSH tunnel stopped")
            val p = profile ?: throw IOException("No SSH profile")

            runCatching { client?.disconnect() }
            client = null

            val config = DefaultConfig().apply { keepAliveProvider = KeepAliveProvider.KEEP_ALIVE }
            val c = SSHClient(config)
            connecting = c
            try {
                // Servers sold to end users rotate/reinstall often; a pinned host key would only
                // produce confusing failures, so the key is accepted as presented.
                c.addHostKeyVerifier(PromiscuousVerifier())
                if (p.security.equals("tls", true)) c.socketFactory = TlsSocketFactory(p.sni, p.server.orEmpty(), p.insecure != false)
                c.connectTimeout = CONNECT_TIMEOUT_MS
                c.connect(p.server.orEmpty(), p.serverPort.orEmpty().toInt())
                c.connection.keepAlive.keepAliveInterval = KEEPALIVE_SECONDS
                c.authPassword(p.username.orEmpty(), p.password.orEmpty())
            } catch (e: Exception) {
                runCatching { c.disconnect() }
                if (e is IOException) throw e
                throw IOException(e.message ?: e.javaClass.simpleName, e)
            } finally {
                connecting = null
            }

            if (gen != generation) {
                runCatching { c.disconnect() }
                throw IOException("SSH tunnel stopped")
            }
            client = c
            return c
        }
    }

    private fun describe(e: Throwable): String {
        val msg = e.message?.takeUnless { it.isBlank() } ?: e.javaClass.simpleName
        return "SSH: $msg"
    }

    // ── Local SOCKS5 server ────────────────────────────────────────────────────────────────────

    private fun acceptLoop(ss: ServerSocket, executor: ExecutorService, gen: Int) {
        while (!ss.isClosed && gen == generation) {
            val s = try {
                ss.accept()
            } catch (_: IOException) {
                break
            }
            try {
                executor.execute { handleClient(s, executor, gen) }
            } catch (_: RejectedExecutionException) {
                runCatching { s.close() }
                break
            }
        }
    }

    private fun handleClient(sock: Socket, executor: ExecutorService, gen: Int) {
        var channel: net.schmizz.sshj.connection.channel.direct.DirectConnection? = null
        try {
            sock.tcpNoDelay = true
            sock.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = sock.getInputStream()
            val output = sock.getOutputStream()

            // greeting: VER NMETHODS METHODS...  -> we always pick "no authentication"
            if (input.read() != 5) return
            val nMethods = input.read()
            if (nMethods < 0) return
            readFully(input, nMethods)
            output.write(byteArrayOf(5, 0))
            output.flush()

            // request: VER CMD RSV ATYP DST.ADDR DST.PORT
            val header = readFully(input, 4)
            if (header[0].toInt() != 5) return
            val cmd = header[1].toInt()
            val host = when (header[3].toInt()) {
                1 -> InetAddress.getByAddress(readFully(input, 4)).hostAddress.orEmpty()
                3 -> {
                    val len = input.read()
                    if (len <= 0) return
                    String(readFully(input, len), Charsets.UTF_8)
                }
                4 -> InetAddress.getByAddress(readFully(input, 16)).hostAddress.orEmpty()
                else -> {
                    reply(output, 8) // address type not supported
                    return
                }
            }
            val portBytes = readFully(input, 2)
            val port = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            if (cmd == 3) { // UDP ASSOCIATE: carried through the udpgw service of the SSH server
                handleUdpAssociate(sock, input, output, executor, gen)
                return
            }
            if (cmd != 1) { // BIND is not possible over SSH
                reply(output, 7)
                return
            }

            val ch = try {
                ensureConnected(gen).newDirectConnection(host, port)
            } catch (e: Exception) {
                LogUtil.w(AppConfig.TAG, "SSH direct-tcpip to $host:$port failed: ${e.message}")
                reply(output, 5) // connection refused / general failure
                return
            }
            channel = ch

            reply(output, 0)
            sock.soTimeout = 0

            val channelIn = ch.inputStream
            val channelOut = ch.outputStream
            val closer = { closeQuietly(sock, ch) }

            // client -> ssh on a worker thread, ssh -> client right here. When the client only finishes
            // sending (half-close, e.g. after an upload) the SSH channel gets an EOF but stays open, so
            // the server's answer can still arrive; any other end closes the pair.
            executor.execute { pump(input, channelOut, closer, onEof = { runCatching { channelOut.close() } }) }
            pump(channelIn, output, closer)
        } catch (_: EOFException) {
            // client went away during the handshake
        } catch (e: Exception) {
            LogUtil.d(AppConfig.TAG, "SSH socks session ended: ${e.message}")
        } finally {
            closeQuietly(sock, channel)
        }
    }

    // ── UDP over SSH (badvpn-udpgw) ────────────────────────────────────────────────────────────

    private const val DEFAULT_UDPGW_PORT = 7300
    private const val UDP_IDLE_TIMEOUT_MS = 5 * 60_000
    private const val MAX_UDP_FLOWS = 256

    /**
     * SOCKS5 UDP ASSOCIATE: opens a loopback UDP socket for the core, and relays its datagrams through one
     * `direct-tcpip` channel to the udpgw service on the SSH server. Needs `badvpn-udpgw` listening on
     * 127.0.0.1:<udpgw port> there; without it the request is refused and apps fall back to TCP.
     */
    private fun handleUdpAssociate(sock: Socket, input: InputStream, output: OutputStream, executor: ExecutorService, gen: Int) {
        val gwPort = profile?.udpgwPort ?: DEFAULT_UDPGW_PORT
        if (gwPort !in 1..65535) {
            reply(output, 7)
            return
        }
        var udp: DatagramSocket? = null
        var channel: net.schmizz.sshj.connection.channel.direct.DirectConnection? = null
        try {
            channel = try {
                ensureConnected(gen).newDirectConnection(AppConfig.LOOPBACK, gwPort)
            } catch (e: Exception) {
                LogUtil.w(AppConfig.TAG, "udpgw on port $gwPort is not reachable: ${e.message}")
                reply(output, 5)
                return
            }
            val u = DatagramSocket(0, InetAddress.getByName(AppConfig.LOOPBACK))
            udp = u
            u.soTimeout = UDP_IDLE_TIMEOUT_MS
            output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (u.localPort shr 8).toByte(), (u.localPort and 0xFF).toByte()))
            output.flush()
            sock.soTimeout = 0

            val ch = channel
            val chOut = ch.outputStream
            val chIn = ch.inputStream
            val flows = HashMap<String, Int>()
            val flowAddr = HashMap<Int, ByteArray>()
            var nextId = 0
            val clientRef = java.util.concurrent.atomic.AtomicReference<java.net.SocketAddress?>(null)
            val closeAll = { runCatching { u.close() }; runCatching { ch.close() }; runCatching { sock.close() }; Unit }

            // core -> udpgw
            executor.execute {
                val buf = ByteArray(65535)
                try {
                    while (true) {
                        val pkt = DatagramPacket(buf, buf.size)
                        u.receive(pkt)
                        clientRef.set(pkt.socketAddress)
                        val d = UdpGwProto.parseSocksUdp(buf, pkt.length) ?: continue
                        val addr = d.addr ?: runCatching {
                            InetAddress.getAllByName(d.host).firstOrNull { it is Inet4Address }?.address
                        }.getOrNull() ?: continue
                        val key = addr.joinToString(".") { (it.toInt() and 0xFF).toString() } + ":" + d.port
                        val id = flows.getOrPut(key) {
                            if (flows.size >= MAX_UDP_FLOWS) { flows.clear(); flowAddr.clear() }
                            val n = nextId++ and 0xFFFF
                            flowAddr[n] = addr
                            n
                        }
                        val frame = UdpGwProto.encode(id, addr, d.port, d.data)
                        synchronized(chOut) { chOut.write(frame); chOut.flush() }
                    }
                } catch (_: Exception) {
                } finally {
                    closeAll()
                }
            }
            // udpgw -> core
            executor.execute {
                try {
                    while (true) {
                        val f = UdpGwProto.read(chIn) ?: break
                        if (f.isKeepAlive || f.addr.isEmpty()) continue
                        val to = clientRef.get() ?: continue
                        val out = UdpGwProto.buildSocksUdp(f.addr, f.port, f.data)
                        u.send(DatagramPacket(out, out.size, to))
                    }
                } catch (_: Exception) {
                } finally {
                    closeAll()
                }
            }
            // the association lives as long as this TCP control connection
            while (input.read() >= 0) { /* ignore */ }
        } catch (e: Exception) {
            LogUtil.d(AppConfig.TAG, "SSH udp associate ended: ${e.message}")
        } finally {
            runCatching { udp?.close() }
            runCatching { channel?.close() }
        }
    }

    /** SSH over TLS: a TLS client socket with the configured SNI (certificates are only checked when [insecure] is off). */
    private class TlsSocketFactory(sni: String?, host: String, insecure: Boolean) : SocketFactory() {
        private val serverName: String? = sni?.takeIf { it.isNotBlank() }
            ?: host.takeIf { it.isNotBlank() && !it.contains(':') && !it.all { c -> c.isDigit() || c == '.' } }
        private val factory: SSLSocketFactory = if (insecure) {
            val trustAll = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>?, authType: String?) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
            }
            SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustAll), SecureRandom()) }.socketFactory
        } else {
            SSLContext.getDefault().socketFactory
        }

        private fun configure(s: Socket): Socket {
            val ssl = s as SSLSocket
            serverName?.let { name ->
                ssl.sslParameters = ssl.sslParameters.apply { serverNames = listOf(SNIHostName(name)) }
            }
            return ssl
        }

        override fun createSocket(): Socket = configure(factory.createSocket())
        override fun createSocket(host: String?, port: Int): Socket = configure(factory.createSocket(host, port))
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            configure(factory.createSocket(host, port, localHost, localPort))
        override fun createSocket(host: InetAddress?, port: Int): Socket = configure(factory.createSocket(host, port))
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            configure(factory.createSocket(address, port, localAddress, localPort))
    }

    private fun pump(from: InputStream, to: OutputStream, onEnd: () -> Unit, onEof: (() -> Unit)? = null) {
        val buf = ByteArray(BUFFER_SIZE)
        var failed = false
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(buf, 0, n)
                to.flush()
            }
        } catch (e: Exception) {
            // either side closed, that ends the pair
            failed = true
            LogUtil.d(AppConfig.TAG, "SSH pump ended: ${e.message}")
        } finally {
            if (!failed && onEof != null) onEof() else onEnd()
        }
    }

    private fun closeQuietly(sock: Socket, ch: net.schmizz.sshj.connection.channel.direct.DirectConnection?) {
        runCatching { sock.close() }
        runCatching { ch?.close() }
    }

    private fun reply(out: OutputStream, code: Int) {
        out.write(byteArrayOf(5, code.toByte(), 0, 1, 0, 0, 0, 0, 0, 0))
        out.flush()
    }

    @Throws(IOException::class)
    private fun readFully(input: InputStream, n: Int): ByteArray {
        val b = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(b, off, n - off)
            if (r < 0) throw EOFException()
            off += r
        }
        return b
    }
}
