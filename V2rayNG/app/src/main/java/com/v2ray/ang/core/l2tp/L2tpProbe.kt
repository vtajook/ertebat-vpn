package com.v2ray.ang.core.l2tp

import java.net.InetAddress

/** Latency probe for L2TP/IPsec profiles: the round trip of the first IKE message on UDP 500. */
object L2tpProbe {
    /** @return milliseconds, or -1 when the server did not answer. */
    fun measure(server: String?): Long {
        if (server.isNullOrBlank()) return -1
        return try {
            val addr = InetAddress.getAllByName(server).firstOrNull { it.address.size == 4 } ?: return -1
            Ike1.probe(addr, { }, { })
        } catch (_: Throwable) {
            -1
        }
    }
}
