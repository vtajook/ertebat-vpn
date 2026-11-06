package com.v2ray.ang.core.routing

import android.content.Context
import android.net.IpPrefix
import android.os.Build
import java.net.InetAddress
import android.net.VpnService
import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import java.io.BufferedInputStream
import java.io.File
import java.io.InputStream

/**
 * Applies the "direct" IP rules of the routing settings (LAN, Iran, ...) to engines that bypass Xray, i.e.
 * OpenVPN, Cisco AnyConnect and L2TP. A [VpnService] can only route by IP, so the direct ranges are cut out
 * of the default routes of the tunnel: traffic to them leaves through the normal network instead.
 * Domain rules cannot be applied here (the destination is not known by name), `.ir` sites are covered
 * by their Iranian addresses.
 */
object DirectRoutes {

    private val PRIVATE_V4 = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
        "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3",
    )

    @Volatile
    private var cache: Pair<String, List<LongRange>>? = null

    /** Ranges that must bypass the tunnel according to the enabled routing rules, merged and sorted. */
    fun directRanges(context: Context): List<LongRange> {
        // Parsing geoip.dat takes a moment: keep the result while rules and the data file stay the same.
        val geo = File(Utils.userAssetPath(context), AppConfig.GEOIP_DAT)
        val signature = MmkvManager.decodeRoutingRulesets().orEmpty()
            .filter { it.enabled && it.outboundTag == AppConfig.TAG_DIRECT }
            .joinToString("|") { "${it.ip}/${it.port}" } + "#" + geo.length() + "@" + geo.lastModified()
        cache?.let { if (it.first == signature) return it.second }
        return computeDirectRanges(context).also { cache = signature to it }
    }

    private fun computeDirectRanges(context: Context): List<LongRange> {
        val rules = MmkvManager.decodeRoutingRulesets().orEmpty()
            .filter { it.enabled && it.outboundTag == AppConfig.TAG_DIRECT && !it.ip.isNullOrEmpty() && it.port.isNullOrEmpty() }
        if (rules.isEmpty()) return emptyList()

        val ranges = ArrayList<LongRange>()
        val countries = HashSet<String>()
        for (rule in rules) for (entry in rule.ip.orEmpty()) {
            val e = entry.trim().lowercase()
            when {
                e == "geoip:private" -> PRIVATE_V4.forEach { parseCidr(it)?.let(ranges::add) }
                e.startsWith("geoip:") -> countries.add(e.removePrefix("geoip:").uppercase())
                else -> parseCidr(e)?.let(ranges::add)
            }
        }
        if (countries.isNotEmpty()) ranges.addAll(readGeoIp(context, countries))
        return merge(ranges)
    }

    private fun parseCidr(text: String): LongRange? {
        val slash = text.indexOf('/')
        val addr = if (slash < 0) text else text.substring(0, slash)
        val prefix = if (slash < 0) 32 else text.substring(slash + 1).toIntOrNull() ?: return null
        val parts = addr.split('.')
        if (parts.size != 4 || prefix !in 0..32) return null
        var v = 0L
        for (p in parts) v = (v shl 8) or ((p.toIntOrNull() ?: return null).toLong() and 0xFF)
        return rangeOf(v, prefix)
    }

    private fun rangeOf(ip: Long, prefix: Int): LongRange {
        val size = 1L shl (32 - prefix)
        val start = ip and (size - 1).inv() and 0xFFFFFFFFL
        return start..(start + size - 1)
    }

    private fun merge(list: List<LongRange>): List<LongRange> {
        val sorted = list.sortedBy { it.first }
        val out = ArrayList<LongRange>()
        for (r in sorted) {
            val last = out.lastOrNull()
            if (last != null && r.first <= last.last + 1) {
                if (r.last > last.last) out[out.size - 1] = last.first..r.last
            } else out.add(r)
        }
        return out
    }

    /** IPv4 ranges of the given country codes from geoip.dat (user-downloaded copy first, then the built-in one). */
    private fun readGeoIp(context: Context, countries: Set<String>): List<LongRange> {
        val user = File(Utils.userAssetPath(context), AppConfig.GEOIP_DAT)
        val stream: InputStream = try {
            if (user.isFile) user.inputStream() else context.assets.open(AppConfig.GEOIP_DAT)
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "DirectRoutes: no geoip.dat (${e.message})")
            return emptyList()
        }
        val out = ArrayList<LongRange>()
        val found = HashSet<String>()
        BufferedInputStream(stream, 1 shl 16).use { input ->
            while (found.size < countries.size) {
                val tag = readVarint(input) ?: break
                if ((tag and 7L) != 2L) break // GeoIPList only has length-delimited entries
                val len = (readVarint(input) ?: break).toInt()
                val entry = ByteArray(len)
                var off = 0
                while (off < len) {
                    val n = input.read(entry, off, len - off)
                    if (n < 0) break
                    off += n
                }
                if (off < len) break
                if ((tag shr 3) != 1L) continue
                val code = parseGeoIp(entry, countries, out) ?: continue
                found.add(code)
            }
        }
        if (found.size < countries.size) {
            LogUtil.w(AppConfig.TAG, "DirectRoutes: geoip.dat has no entry for ${countries - found}")
        }
        return out
    }

    /** Reads one GeoIP message; adds its IPv4 CIDRs to [out] when the country is wanted and returns the code. */
    private fun parseGeoIp(buf: ByteArray, wanted: Set<String>, out: MutableList<LongRange>): String? {
        var pos = 0
        var code: String? = null
        val cidrs = ArrayList<LongRange>()
        while (pos < buf.size) {
            val (tag, p1) = varintAt(buf, pos)
            pos = p1
            val field = (tag shr 3).toInt()
            when ((tag and 7L).toInt()) {
                0 -> pos = varintAt(buf, pos).second
                2 -> {
                    val (len, p2) = varintAt(buf, pos)
                    val end = p2 + len.toInt()
                    if (field == 1) code = String(buf, p2, len.toInt(), Charsets.UTF_8).uppercase()
                    else if (field == 2) parseCidrMsg(buf, p2, end)?.let(cidrs::add)
                    pos = end
                }
                else -> return null
            }
        }
        if (code == null || code !in wanted) return null
        out.addAll(cidrs)
        return code
    }

    private fun parseCidrMsg(buf: ByteArray, start: Int, end: Int): LongRange? {
        var pos = start
        var ip: ByteArray? = null
        var prefix = 0
        while (pos < end) {
            val (tag, p1) = varintAt(buf, pos)
            pos = p1
            when ((tag and 7L).toInt()) {
                0 -> {
                    val (v, p2) = varintAt(buf, pos)
                    if ((tag shr 3).toInt() == 2) prefix = v.toInt()
                    pos = p2
                }
                2 -> {
                    val (len, p2) = varintAt(buf, pos)
                    if ((tag shr 3).toInt() == 1) ip = buf.copyOfRange(p2, p2 + len.toInt())
                    pos = p2 + len.toInt()
                }
                else -> return null
            }
        }
        val b = ip ?: return null
        if (b.size != 4) return null // IPv6 ranges are not handled
        var v = 0L
        for (x in b) v = (v shl 8) or (x.toLong() and 0xFF)
        return rangeOf(v, prefix)
    }

    private fun varintAt(buf: ByteArray, start: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = start
        while (true) {
            val b = buf[pos++].toInt()
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) break
            shift += 7
        }
        return result to pos
    }

    private fun readVarint(input: InputStream): Long? {
        var result = 0L
        var shift = 0
        while (true) {
            val b = input.read()
            if (b < 0) return null
            result = result or ((b and 0x7F).toLong() shl shift)
            if (b and 0x80 == 0) return result
            shift += 7
        }
    }

    /**
     * Collects the IPv4 routes of a tunnel and writes them to the builder. Wide routes (prefix < 8, i.e.
     * "everything" or its halves) lose the [direct] ranges; narrower routes the server pushed on purpose stay.
     */
    class Collector(private val builder: VpnService.Builder, private val direct: List<LongRange>) {
        private val included = ArrayList<Pair<Long, Int>>()
        private val pinned = ArrayList<Long>() // addresses that must stay reachable through the tunnel (DNS)

        fun addRoute(address: String, prefix: Int) {
            val v = parseCidr("$address/$prefix")
            if (v == null) {
                builder.addRoute(address, prefix) // IPv6 or unparsable: untouched
                return
            }
            included.add(v.first to prefix)
        }

        fun pin(address: String) {
            parseCidr(address)?.let { pinned.add(it.first) }
        }

        fun apply() {
            val wide = ArrayList<LongRange>()
            for ((start, prefix) in included) {
                val r = rangeOf(start, prefix)
                if (direct.isEmpty() || prefix >= 8) builder.addRoute(toIp(r.first), prefix) else wide.add(r)
            }
            val merged = merge(wide)
            // Direct ranges are cut out of the wide routes (plain included routes, no excludeRoute): with
            // excluded routes some apps (e.g. Claude) saw the network as offline for a few seconds on every
            // new connection, which the official OpenVPN app does not.
            for (r in merged) {
                for (piece in subtract(r, direct)) for ((ip, p) in toCidrs(piece)) builder.addRoute(toIp(ip), p)
            }
            for (ip in pinned) runCatching { builder.addRoute(toIp(ip), 32) }
        }

        private fun subtract(r: LongRange, cuts: List<LongRange>): List<LongRange> {
            val out = ArrayList<LongRange>()
            var cur = r.first
            for (c in cuts) {
                if (c.last < cur) continue
                if (c.first > r.last) break
                if (c.first > cur) out.add(cur..(c.first - 1))
                cur = maxOf(cur, c.last + 1)
                if (cur > r.last) break
            }
            if (cur <= r.last) out.add(cur..r.last)
            return out
        }

        private fun toCidrs(r: LongRange): List<Pair<Long, Int>> {
            val out = ArrayList<Pair<Long, Int>>()
            var start = r.first
            val end = r.last
            while (start <= end) {
                var size = if (start == 0L) 1L shl 32 else start and -start
                while (start + size - 1 > end) size = size shr 1
                out.add(start to (32 - java.lang.Long.numberOfTrailingZeros(size)))
                start += size
            }
            return out
        }

        private fun toIp(v: Long) = "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"
    }
}
