package com.v2ray.ang.fmt

import com.v2ray.ang.AppConfig
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.util.Utils

/**
 * SSH profile link: `ssh://user:pass@host:port#name`.
 *
 * The parser is deliberately tolerant instead of relying on [java.net.URI]: passwords are split off
 * at the LAST `@`, so a password that itself contains `@`, `#` or `:` still imports correctly when it
 * is percent-encoded, and unencoded `@`/`:` inside the password also work.
 */
object SshFmt : FmtBase() {

    const val DEFAULT_SSH_PORT = 22
    const val DEFAULT_UDPGW_PORT = 7300

    /**
     * Parses `ssh://user:pass@host:port#name`.
     *
     * @return the parsed profile, or null when the link has no host, no user or an invalid port.
     */
    fun parse(str: String): ProfileItem? {
        var body = str.trim()
        if (!body.startsWith(AppConfig.SSH, ignoreCase = true)) return null
        body = body.substring(AppConfig.SSH.length)

        // fragment = display name
        var remarks = ""
        val hashIdx = body.lastIndexOf('#')
        if (hashIdx >= 0) {
            remarks = Utils.decodeURIComponent(body.substring(hashIdx + 1))
            body = body.substring(0, hashIdx)
        }

        // optional query/path, e.g. ssh://u:p@h:22/?security=tls&sni=x&udpgw=7300
        var query = ""
        val cut = body.indexOfAny(charArrayOf('?', '/'), startIndex = body.lastIndexOf('@').coerceAtLeast(0))
        if (cut >= 0) {
            val q = body.indexOf('?', cut)
            if (q >= 0) query = body.substring(q + 1)
            body = body.substring(0, cut)
        }
        val params = query.split('&').filter { it.contains('=') }.associate {
            Utils.decodeURIComponent(it.substringBefore('=')).lowercase() to Utils.decodeURIComponent(it.substringAfter('='))
        }

        val at = body.lastIndexOf('@')
        if (at <= 0) return null
        val userInfo = body.substring(0, at)
        val hostPort = body.substring(at + 1)

        val colon = userInfo.indexOf(':')
        val user = Utils.decodeURIComponent(if (colon >= 0) userInfo.substring(0, colon) else userInfo)
        val pass = if (colon >= 0) Utils.decodeURIComponent(userInfo.substring(colon + 1)) else ""
        if (user.isEmpty()) return null

        val host: String
        val port: Int
        if (hostPort.startsWith("[")) {
            // [ipv6]:port
            val close = hostPort.indexOf(']')
            if (close < 0) return null
            host = hostPort.substring(1, close)
            val rest = hostPort.substring(close + 1)
            port = if (rest.startsWith(":")) rest.substring(1).toIntOrNull() ?: return null else DEFAULT_SSH_PORT
        } else {
            val pc = hostPort.lastIndexOf(':')
            if (pc >= 0) {
                host = hostPort.substring(0, pc)
                port = hostPort.substring(pc + 1).toIntOrNull() ?: return null
            } else {
                host = hostPort
                port = DEFAULT_SSH_PORT
            }
        }
        if (host.isEmpty() || port !in 1..65535) return null

        val config = ProfileItem.create(EConfigType.SSH)
        config.remarks = remarks.ifEmpty { "$user@$host" }
        config.server = host
        config.serverPort = port.toString()
        config.username = user
        config.password = pass

        val security = (params["security"] ?: params["tls"] ?: "").lowercase()
        if (security == "tls" || security == "1" || security == "true" || params.containsKey("sni")) {
            config.security = "tls"
            config.sni = (params["sni"] ?: params["servername"] ?: params["serversni"] ?: params["peer"] ?: params["host"]).orEmpty()
            val insecure = params["allowinsecure"] ?: params["insecure"]
            config.insecure = insecure == null || insecure == "1" || insecure.equals("true", true)
        }
        config.udpgwPort = (params["udpgw"] ?: params["udpgwport"] ?: params["udpgw_port"])?.toIntOrNull() ?: DEFAULT_UDPGW_PORT
        return config
    }

    /**
     * Builds everything after the `ssh://` scheme: `user:pass@host:port#name`.
     * (The caller prepends [EConfigType.protocolScheme].)
     */
    fun toUri(config: ProfileItem): String {
        val user = Utils.encodeURIComponent(config.username.orEmpty())
        val pass = Utils.encodeURIComponent(config.password.orEmpty())
        val host = Utils.getIpv6Address(config.server.orEmpty())
        val q = mutableListOf<String>()
        if (config.security.equals("tls", true)) {
            q += "security=tls"
            if (!config.sni.isNullOrBlank()) q += "sni=" + Utils.encodeURIComponent(config.sni.orEmpty())
            q += "allowInsecure=" + if (config.insecure == false) "0" else "1"
        }
        config.udpgwPort?.let { q += "udpgw=$it" }
        val query = if (q.isEmpty()) "" else "?" + q.joinToString("&")
        return "$user:$pass@$host:${config.serverPort}$query#${Utils.encodeURIComponent(config.remarks)}"
    }
}
