package com.v2ray.ang.core.ovpn

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.AppConfig

/**
 * Latency probe for an OpenVPN profile: runs the real handshake (transport, TLS, authentication) up to
 * the point where the server hands out the tunnel settings, takes the time, and stops before any tunnel
 * is created. UDP servers cannot be tested any other way (they ignore unauthenticated packets).
 */
object OpenVpnProbe {
    private const val TIMEOUT_MS = 15_000L
    private val done = setOf("GET_CONFIG", "ASSIGN_IP", "ADD_ROUTES", "CONNECTED")
    private val fatal = setOf("AUTH_FAILED", "CONNECTION_TIMEOUT", "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "CLIENT_HALT", "NEED_CREDS")

    private val lock = Any()

    /** @return milliseconds until the handshake completed, or -1 when it did not. */
    fun measure(profile: ProfileItem): Long = synchronized(lock) {
        val ovpn = profile.ovpnConfig ?: return -1L
        var result = -1L
        var engine: OpenVpnEngine? = null
        val start = System.nanoTime()
        val finished = java.util.concurrent.atomic.AtomicBoolean(false)

        val listener = object : OpenVpnEngine.Listener {
            override fun onState(name: String, info: String) {
                if (name in done && result < 0) {
                    result = (System.nanoTime() - start) / 1_000_000
                }
                if (name in done || name in fatal) {
                    // stop from another thread: this callback runs inside the core
                    Thread { runCatching { engine?.stop() } }.start()
                }
            }

            override fun onLog(line: String) {}
        }

        return try {
            val e = OpenVpnEngine(null, listener)
            engine = e
            val error = e.configure(ovpn, profile.username, profile.password)
            if (error != null) {
                LogUtil.w(AppConfig.TAG, "OpenVPN probe: $error")
                return -1L
            }
            val watchdog = Thread {
                try {
                    Thread.sleep(TIMEOUT_MS)
                    if (!finished.get()) e.stop()
                } catch (_: InterruptedException) {
                }
            }.also { it.isDaemon = true; it.start() }
            e.run()
            finished.set(true)
            watchdog.interrupt()
            result
        } catch (t: Throwable) {
            LogUtil.w(AppConfig.TAG, "OpenVPN probe failed: ${t.message}")
            -1L
        }
    }
}
