package com.v2ray.ang.core.ovpn

import android.net.IpPrefix
import android.net.VpnService
import android.os.Build
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.routing.DirectRoutes
import com.v2ray.ang.util.LogUtil
import net.openvpn.ovpn3.ClientAPI_AppCustomControlMessageEvent
import net.openvpn.ovpn3.ClientAPI_Config
import net.openvpn.ovpn3.ClientAPI_Event
import net.openvpn.ovpn3.ClientAPI_ExternalPKICertRequest
import net.openvpn.ovpn3.ClientAPI_ExternalPKISignRequest
import net.openvpn.ovpn3.ClientAPI_LogInfo
import net.openvpn.ovpn3.ClientAPI_OpenVPNClient
import net.openvpn.ovpn3.ClientAPI_ProvideCreds
import net.openvpn.ovpn3.DnsOptions
import java.net.InetAddress

/**
 * OpenVPN 3 core (AGPL-3.0, built from the `third_party/openvpn3` submodule) driven through its SWIG
 * bindings. The core calls the `tun_builder_*` methods while connecting; they are translated into a
 * [VpnService.Builder] of [service], and the finished tun file descriptor is handed back to the core.
 *
 * [connect] blocks until the session ends, so it must run on a worker thread.
 */
class OpenVpnEngine(
    private val service: VpnService?,
    private val listener: Listener,
) : ClientAPI_OpenVPNClient() {

    interface Listener {
        fun onState(name: String, info: String)
        fun onLog(line: String)
    }

    private var builder: VpnService.Builder? = null
    private var routes: DirectRoutes.Collector? = null
    private var dnsAdded = false
    private var sessionName = AppConfigName

    /** Parses [ovpn] and applies the credentials. Returns an error text, or null when the config is usable. */
    fun configure(ovpn: String, username: String?, password: String?, protoOverride: String? = null): String? {
        val config = ClientAPI_Config()
        config.content = ovpn
        config.tunPersist = false
        config.guiVersion = "EGN VPN 1.0"
        config.info = true
        config.compressionMode = "asym"
        config.connTimeout = CONNECT_TIMEOUT_SECONDS
        config.retryOnAuthFailed = false
        if (protoOverride == "udp" || protoOverride == "tcp") config.protoOverride = protoOverride

        val eval = eval_config(config)
        if (eval.error) return eval.message.ifBlank { "Invalid OpenVPN config" }

        if (!username.isNullOrEmpty()) {
            val creds = ClientAPI_ProvideCreds()
            creds.username = username
            creds.password = password.orEmpty()
            val status = provide_creds(creds)
            if (status.error) return status.message.ifBlank { "Invalid credentials" }
        }
        return null
    }

    /** Connects and blocks. Returns an error text, or null when the session ended normally. */
    fun run(): String? {
        val status = connect()
        return if (status.error) "${status.status}: ${status.message}".trim(':', ' ') else null
    }

    fun bytesIn(): Long = transport_stats().bytesIn
    fun bytesOut(): Long = transport_stats().bytesOut

    // ── tun builder ────────────────────────────────────────────────────────────────────────────

    override fun tun_builder_new(): Boolean {
        val b = service?.Builder()?.setBlocking(false)
        builder = b
        routes = if (b != null && service != null) {
            DirectRoutes.Collector(b, runCatching { DirectRoutes.directRanges(service) }.getOrDefault(emptyList()))
        } else null
        dnsAdded = false
        return true
    }

    override fun tun_builder_set_layer(layer: Int): Boolean = layer == 3

    override fun tun_builder_set_remote_address(address: String, ipv6: Boolean): Boolean = true

    override fun tun_builder_add_address(
        address: String, prefixLength: Int, gateway: String, ipv6: Boolean, net30: Boolean,
    ): Boolean = guard { builder?.addAddress(address, prefixLength) }

    override fun tun_builder_set_route_metric_default(metric: Int): Boolean = true

    override fun tun_builder_reroute_gw(ipv4: Boolean, ipv6: Boolean, flags: Long): Boolean = guard {
        if (ipv4) routes?.addRoute("0.0.0.0", 0)
        if (ipv6) builder?.addRoute("::", 0)
    }

    override fun tun_builder_add_route(address: String, prefixLength: Int, metric: Int, ipv6: Boolean): Boolean =
        guard { if (ipv6) builder?.addRoute(address, prefixLength) else routes?.addRoute(address, prefixLength) }

    override fun tun_builder_exclude_route(address: String, prefixLength: Int, metric: Int, ipv6: Boolean): Boolean =
        guard {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                builder?.excludeRoute(IpPrefix(InetAddress.getByName(address), prefixLength))
            }
        }

    override fun tun_builder_set_dns_options(dns: DnsOptions): Boolean = guard {
        val servers = dns.servers
        for (key in servers.keys) {
            val server = servers[key] ?: continue
            for (address in server.addresses) {
                if (address.port == 0L || address.port == 53L) {
                    builder?.addDnsServer(address.address)
                    routes?.pin(address.address)
                    dnsAdded = true
                }
            }
        }
        for (domain in dns.search_domains) {
            builder?.addSearchDomain(domain.domain)
        }
    }

    override fun tun_builder_set_mtu(mtu: Int): Boolean = guard { builder?.setMtu(mtu) }

    override fun tun_builder_set_session_name(name: String): Boolean {
        sessionName = name
        return guard { builder?.setSession(name) }
    }

    override fun tun_builder_add_proxy_bypass(bypassHost: String): Boolean = true
    override fun tun_builder_set_proxy_auto_config_url(url: String): Boolean = true
    override fun tun_builder_set_proxy_http(host: String, port: Int): Boolean = true
    override fun tun_builder_set_proxy_https(host: String, port: Int): Boolean = true
    override fun tun_builder_add_wins_server(address: String): Boolean = true
    override fun tun_builder_set_allow_family(af: Int, allow: Boolean): Boolean = true
    override fun tun_builder_set_allow_local_dns(allow: Boolean): Boolean = true
    override fun tun_builder_persist(): Boolean = false
    override fun tun_builder_teardown(disconnect: Boolean) {}

    override fun tun_builder_establish(): Int {
        // no service = latency probe: the tunnel is never brought up
        val b = builder ?: return -1
        return try {
            if (!dnsAdded) {
                // the server pushed no DNS: use public resolvers so name lookups still work inside the tunnel
                b.addDnsServer("1.1.1.1")
                b.addDnsServer("8.8.8.8")
            }
            b.setSession(sessionName)
            routes?.apply()
            val pfd = b.establish()
            if (pfd == null) -1 else pfd.detachFd()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "OpenVPN: establish failed", e)
            -1
        }
    }

    override fun socket_protect(socket: Int, remote: String, ipv6: Boolean): Boolean = service?.protect(socket) ?: true

    // ── core callbacks ─────────────────────────────────────────────────────────────────────────

    override fun event(event: ClientAPI_Event) {
        listener.onState(event.name, event.info)
    }

    override fun log(info: ClientAPI_LogInfo) {
        listener.onLog(info.text.trimEnd('\n'))
    }

    override fun pause_on_connection_timeout(): Boolean = false

    override fun acc_event(event: ClientAPI_AppCustomControlMessageEvent) {}

    override fun external_pki_cert_request(request: ClientAPI_ExternalPKICertRequest) {
        request.error = true
        request.errorText = "External PKI is not supported"
    }

    override fun external_pki_sign_request(request: ClientAPI_ExternalPKISignRequest) {
        request.error = true
        request.errorText = "External PKI is not supported"
    }

    private inline fun guard(block: () -> Unit): Boolean = try {
        block()
        true
    } catch (e: Exception) {
        LogUtil.w(AppConfig.TAG, "OpenVPN tun builder: ${e.message}")
        false
    }

    companion object {
        private const val AppConfigName = "EGN VPN"
        private const val CONNECT_TIMEOUT_SECONDS = 45

        init {
            System.loadLibrary("ovpn3")
        }
    }
}
