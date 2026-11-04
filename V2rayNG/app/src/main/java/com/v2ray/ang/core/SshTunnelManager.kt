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

            if (cmd != 1) { // only CONNECT; no BIND / UDP ASSOCIATE over SSH
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

            // client -> ssh on a worker thread, ssh -> client right here
            executor.execute { pump(input, channelOut, closer) }
            pump(channelIn, output, closer)
        } catch (_: EOFException) {
            // client went away during the handshake
        } catch (e: Exception) {
            LogUtil.d(AppConfig.TAG, "SSH socks session ended: ${e.message}")
        } finally {
            closeQuietly(sock, channel)
        }
    }

    private fun pump(from: InputStream, to: OutputStream, onEnd: () -> Unit) {
        val buf = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(buf, 0, n)
                to.flush()
            }
        } catch (_: Exception) {
            // either side closed, that ends the pair
        } finally {
            onEnd()
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
