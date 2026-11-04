package com.v2ray.ang.fmt

import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType

/**
 * OpenVPN profiles are imported as whole `.ovpn` files (certificates and keys inline). The file is kept
 * verbatim in [ProfileItem.ovpnConfig]; server, port and protocol are only read out for the list and ping.
 */
object OpenVpnFmt {

    private val remoteRegex = Regex("""(?m)^\s*remote\s+(\S+)(?:\s+(\d+))?(?:\s+(udp|tcp|udp4|tcp4|udp6|tcp6)\S*)?""")
    private val protoRegex = Regex("""(?m)^\s*proto\s+(udp|tcp)\S*""")
    private val clientRegex = Regex("""(?m)^\s*(client|pull)\s*$""")
    private val devRegex = Regex("""(?m)^\s*dev\s+tun""")

    /** True for text that looks like an OpenVPN client config. */
    fun looksLikeOvpn(text: String): Boolean {
        if (remoteRegex.find(text) == null) return false
        return clientRegex.containsMatchIn(text) || devRegex.containsMatchIn(text) || text.contains("<ca>")
    }

    fun parseOvpn(text: String, remarks: String? = null): ProfileItem? {
        val remote = remoteRegex.find(text) ?: return null
        val host = remote.groupValues[1]
        val port = remote.groupValues[2].ifEmpty { "1194" }
        val proto = (remote.groupValues[3].ifEmpty { protoRegex.find(text)?.groupValues?.get(1) ?: "udp" })
            .let { if (it.startsWith("tcp")) "tcp" else "udp" }

        val profile = ProfileItem.create(EConfigType.OPENVPN)
        profile.server = host
        profile.serverPort = port
        profile.mode = proto
        profile.remarks = remarks?.takeIf { it.isNotBlank() } ?: "OpenVPN $host"
        profile.ovpnConfig = text.trim() + "\n"
        return profile
    }

    /** Server / port / protocol of the first `remote` line, null when there is none. */
    fun readRemote(text: String): Triple<String, String, String>? {
        val p = parseOvpn(text) ?: return null
        return Triple(p.server.orEmpty(), p.serverPort.orEmpty(), p.mode.orEmpty())
    }

    /** True when the profile needs a user name and password (`auth-user-pass` without a file). */
    fun needsCredentials(text: String): Boolean =
        Regex("""(?m)^\s*auth-user-pass\s*$""").containsMatchIn(text)
}
