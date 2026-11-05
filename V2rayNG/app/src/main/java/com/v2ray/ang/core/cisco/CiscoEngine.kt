package com.v2ray.ang.core.cisco

import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.routing.DirectRoutes
import com.v2ray.ang.util.LogUtil
import org.infradead.libopenconnect.LibOpenConnect
import java.net.InetAddress

/** The native library has to be loaded before [LibOpenConnect] is initialised (its static init calls into it). */
object OcNative {
    @Volatile
    private var loaded = false

    @Synchronized
    fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary("openconnect")
            loaded = true
        }
    }

    /**
     * Factory lives here on purpose: touching a companion of [CiscoEngine] would initialise the class (and so
     * [LibOpenConnect], whose static init calls into the library) before the library is loaded.
     */
    fun newEngine(
        service: VpnService, remarks: String, username: String, password: String, group: String?,
        listener: CiscoEngine.Listener,
    ): CiscoEngine {
        ensureLoaded()
        return CiscoEngine(service, remarks, username, password, group, listener)
    }
}

/**
 * Cisco AnyConnect client on top of libopenconnect (LGPL-2.1, `third_party/openconnect`). [run] blocks
 * until the session ends, so it belongs on a worker thread; [stop] may be called from any thread.
 */
class CiscoEngine internal constructor(
    private val service: VpnService,
    private val remarks: String,
    private val username: String,
    private val password: String,
    private val group: String?,
    private val listener: Listener,
) : LibOpenConnect("Open AnyConnect VPN Agent v8.10") {

    interface Listener {
        fun onConnected()
        fun onLog(line: String)
    }

    @Volatile
    private var rxBytes = 0L

    @Volatile
    private var txBytes = 0L

    @Volatile
    private var lastError: String? = null
    private var formAttempts = 0

    fun bytesIn(): Long {
        requestStats()
        return rxBytes
    }

    fun bytesOut(): Long = txBytes

    @Volatile
    private var done = false

    fun stop() {
        if (!done) runCatching { cancel() }
    }

    /** @return an error text, or null when the session ended normally (e.g. it was stopped). */
    fun run(server: String, port: Int): String? {
        try {
            setLogLevel(PRG_INFO)
            if (parseURL("https://$server:$port") != 0) return "Invalid server address"
            setProtocol("anyconnect")
            setReportedOS("android")
            if (!group.isNullOrBlank()) setUrlpath(group.trim().trimStart('/'))

            val auth = obtainCookie()
            if (isCanceled) return null
            if (auth != 0) return lastError ?: "Login failed"

            if (makeCSTPConnection() != 0) return lastError ?: "Could not establish the tunnel"
            val ip = getIPInfo() ?: return "The server did not send tunnel settings"
            val fd = establishTun(ip) ?: return "Could not create the VPN interface"
            if (setupTunFD(fd) != 0) return lastError ?: "Could not attach the VPN interface"
            setupDTLS(60)
            setDPD(30)
            listener.onConnected()
            mainloop(90, RECONNECT_INTERVAL_MIN)
            return if (isCanceled) null else lastError ?: "The connection was closed by the server"
        } finally {
            done = true
            runCatching { destroy() }
        }
    }

    // ── callbacks from libopenconnect ──────────────────────────────────────────────────────────

    override fun onProcessAuthForm(authForm: AuthForm): Int {
        if (!authForm.error.isNullOrBlank()) lastError = authForm.error
        formAttempts++
        if (formAttempts > 3 || isCanceled) return OC_FORM_RESULT_CANCELLED
        var textFields = 0
        for (opt in authForm.opts) {
            when (opt.type) {
                OC_FORM_OPT_SELECT -> {
                    val wanted = group?.trim().orEmpty()
                    val index = if (wanted.isEmpty()) -1 else opt.choices.indexOfFirst {
                        it.name.equals(wanted, true) || it.label.equals(wanted, true)
                    }
                    if (index >= 0) {
                        opt.value = opt.choices[index].name
                        if (opt === authForm.authgroupOpt) authForm.authgroupSelection = index
                    } else if (opt.value.isNullOrEmpty() && opt.choices.isNotEmpty()) {
                        opt.value = opt.choices[0].name
                    }
                }

                OC_FORM_OPT_PASSWORD -> opt.value = password
                OC_FORM_OPT_TEXT -> {
                    // first text box is the user name; a second one would be an extra factor we cannot answer
                    opt.value = if (textFields == 0) username else ""
                    textFields++
                }
            }
        }
        return OC_FORM_RESULT_OK
    }

    override fun onProgress(level: Int, msg: String) {
        val line = msg.trim()
        if (line.isEmpty()) return
        if (level == PRG_ERR) lastError = line
        listener.onLog(line)
    }

    // The servers are the customer's own appliances, often with self-signed certificates.
    override fun onValidatePeerCert(msg: String): Int = 0

    override fun onProtectSocket(fd: Int) {
        service.protect(fd)
    }

    override fun onStatsUpdate(stats: VPNStats) {
        rxBytes = stats.rxBytes
        txBytes = stats.txBytes
    }

    // ── tunnel ─────────────────────────────────────────────────────────────────────────────────

    private fun establishTun(ip: IPInfo): Int? {
        val b = service.Builder().setBlocking(false).setSession(remarks.ifBlank { AppConfig.TAG })
        val routes = DirectRoutes.Collector(b, runCatching { DirectRoutes.directRanges(service) }.getOrDefault(emptyList()))
        try {
            val mtu = if (ip.MTU in 1000..1500) ip.MTU else 1400
            b.setMtu(mtu)
            val v4 = ip.addr
            if (!v4.isNullOrBlank()) b.addAddress(v4, prefixOf(ip.netmask, 32).coerceAtMost(32).let { if (it <= 0) 32 else it })
            val v6 = ip.addr6
            if (!v6.isNullOrBlank()) {
                val (a, p) = splitCidr(v6, ip.netmask6)
                b.addAddress(a, if (p in 1..128) p else 128)
            }

            var dns = 0
            for (d in ip.DNS) {
                runCatching { b.addDnsServer(d); routes.pin(d); dns++ }
            }
            if (dns == 0) {
                b.addDnsServer("1.1.1.1")
                b.addDnsServer("8.8.8.8")
            }
            ip.domain?.takeIf { it.isNotBlank() }?.let { runCatching { b.addSearchDomain(it) } }

            if (ip.splitIncludes.isEmpty()) {
                routes.addRoute("0.0.0.0", 0)
                if (!v6.isNullOrBlank()) b.addRoute("::", 0)
            } else {
                for (r in ip.splitIncludes) {
                    val (a, p) = splitCidr(r, null)
                    runCatching { routes.addRoute(a, p) }.onFailure { LogUtil.w(AppConfig.TAG, "Cisco route $r: ${it.message}") }
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                for (r in ip.splitExcludes) {
                    val (a, p) = splitCidr(r, null)
                    runCatching { b.excludeRoute(IpPrefix(InetAddress.getByName(a), p)) }
                }
            }
            routes.apply()
            val pfd = b.establish() ?: return null
            return pfd.detachFd()
        } catch (t: Throwable) {
            lastError = "VPN interface: ${t.message}"
            LogUtil.e(AppConfig.TAG, "Cisco tun setup failed", t)
            return null
        }
    }

    /** "10.0.0.0/255.0.0.0", "10.0.0.0/8", "10.1.2.3" with a separate [mask]; returns address and prefix length. */
    private fun splitCidr(value: String, mask: String?): Pair<String, Int> {
        val slash = value.indexOf('/')
        if (slash < 0) {
            val full = if (value.contains(':')) 128 else 32
            return value to prefixOf(mask, full)
        }
        val addr = value.substring(0, slash)
        val rest = value.substring(slash + 1)
        return addr to prefixOf(rest, if (addr.contains(':')) 128 else 32)
    }

    private fun prefixOf(mask: String?, default: Int): Int {
        if (mask.isNullOrBlank()) return default
        val m = mask.trim().trimStart('/')
        m.toIntOrNull()?.let { return it }
        return runCatching {
            InetAddress.getByName(m).address.sumOf { Integer.bitCount(it.toInt() and 0xFF) }
        }.getOrDefault(default)
    }
}
