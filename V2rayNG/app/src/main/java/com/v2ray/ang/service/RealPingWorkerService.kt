package com.v2ray.ang.service

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.core.CoreConfigManager
import com.v2ray.ang.core.CoreNativeManager
import com.v2ray.ang.core.l2tp.L2tpProbe
import com.v2ray.ang.core.ovpn.OpenVpnProbe
import com.v2ray.ang.dto.RealPingEvent
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.isComplexType
import com.v2ray.ang.extension.isNotNullEmpty
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

internal object RealPingExecutionLimiter {
    private val customConfigMutex = Mutex()

    suspend fun <T> run(configType: EConfigType, block: () -> T): T {
        // Custom profiles bypass speed-test trimming and start complete Xray configs.
        // Parallel teardown can abort the native probe process, so serialize their
        // JNI measurements globally across batches.
        return if (configType == EConfigType.CUSTOM) {
            customConfigMutex.withLock { block() }
        } else {
            block()
        }
    }
}

/**
 * Worker that runs a batch of real-ping tests independently.
 * Each batch owns its own CoroutineScope/dispatcher and can be cancelled separately.
 */
class RealPingWorkerService(
    private val context: Context,
    private val guids: List<String>,
    private val onlyTcp: Boolean = false,
    private val onEvent: (RealPingEvent) -> Unit = {}
) {
    private val job = SupervisorJob()
    private val concurrency = SettingsManager.getRealPingConcurrency()
    private val dispatcher = Executors.newFixedThreadPool(if (onlyTcp) concurrency * 2 else concurrency).asCoroutineDispatcher()
    private val scope = CoroutineScope(job + dispatcher + CoroutineName("RealPingBatchWorker"))

    private val runningCount = AtomicInteger(0)
    private val totalCount = AtomicInteger(0)

    fun start() {
        val jobs = guids.map { guid ->
            totalCount.incrementAndGet()
            scope.launch {
                runningCount.incrementAndGet()
                try {
                    val result = if (onlyTcp) startTcping(guid) else startRealPing(guid)
                    if (scope.isActive) {
                        onEvent(RealPingEvent.Result(guid, result))
                    }
                } catch (_: Throwable) {
                    // ignore
                } finally {
                    val count = totalCount.decrementAndGet()
                    val left = runningCount.decrementAndGet()
                    if (scope.isActive) {
                        onEvent(RealPingEvent.Progress("$left / $count"))
                    }
                }
            }
        }

        scope.launch {
            try {
                joinAll(*jobs.toTypedArray())
                if (isActive) {
                    onEvent(RealPingEvent.Finish("0"))
                }
            } catch (_: CancellationException) {
                // If cancelled, don't send finish event to avoid confusion
            } finally {
                close()
            }
        }
    }

    fun cancel() {
        job.cancel()
    }

    private fun close() {
        try {
            dispatcher.close()
        } catch (_: Throwable) {
            // ignore
        }
    }

    private suspend fun startRealPing(guid: String): Long {
        val retFailure = -1L

        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure
        if (config.configType == EConfigType.OPENVPN) {
            // OpenVPN is not an Xray outbound: only the reachability of the server can be measured. UDP
            // servers cannot be probed by connecting, so they report a nominal value instead.
            val port = config.serverPort?.toIntOrNull() ?: return retFailure
            val udp = when (config.ovpnProto) { "udp", "both" -> true; "tcp" -> false; else -> config.mode == "udp" }
            return if (udp) OpenVpnProbe.measure(config) else SpeedtestManager.socketConnectTime(config.server.orEmpty(), port, 3000)
        }
        if (config.configType == EConfigType.L2TP) {
            // L2TP/IPsec is UDP only: the round trip of the first IKE message is what can be measured
            return L2tpProbe.measure(config.server)
        }
        if (config.configType == EConfigType.ANYCONNECT) {
            // AnyConnect is not an Xray outbound: the reachability of the HTTPS port is what can be measured
            val port = config.serverPort?.toIntOrNull() ?: 443
            return SpeedtestManager.socketConnectTime(config.server.orEmpty(), port, 3000)
        }
        if (config.configType == EConfigType.SSH) {
            // An SSH profile can only be tunnelled while it is connected, so "ping" is the TCP connect time.
            val sshPort = config.serverPort?.toIntOrNull() ?: return retFailure
            return SpeedtestManager.socketConnectTime(config.server.orEmpty(), sshPort, 3000)
        }
        if (!config.configType.isComplexType()
            && config.configType != EConfigType.HYSTERIA2
            && config.configType != EConfigType.WIREGUARD
            && config.alpn?.startsWith("h3") != true
            && config.server.isNotNullEmpty()
            && config.serverPort?.toIntOrNull() != null
        ) {
            val url = config.server.orEmpty()
            val port = config.serverPort.orEmpty().toInt()
            val tcpTime = SpeedtestManager.socketConnectTime(url, port, 1000)
            if (tcpTime <= -1L) {
                return retFailure
            }
        }

        val configResult = CoreConfigManager.getV2rayConfig4Speedtest(context, guid)
        if (!configResult.status) {
            return retFailure
        }
        return RealPingExecutionLimiter.run(config.configType) {
            var delay = CoreNativeManager.measureOutboundDelay(configResult.content, SettingsManager.getDelayTestUrl())
            if (delay < 0 && config.configType == EConfigType.WIREGUARD) {
                // WireGuard needs a UDP handshake (and a DNS lookup through the tunnel) before the first
                // byte flows, so the first probe often times out: try again, then with the second URL.
                delay = CoreNativeManager.measureOutboundDelay(configResult.content, SettingsManager.getDelayTestUrl())
                if (delay < 0) {
                    delay = CoreNativeManager.measureOutboundDelay(configResult.content, SettingsManager.getDelayTestUrl(true))
                }
            }
            delay
        }
    }

    /**
     * Round-trip time of one ICMP echo, in milliseconds, or -1 when the host does not answer.
     * UDP-only servers (OpenVPN over UDP) cannot be probed by connecting, so this is the best estimate.
     */
    private fun icmpPing(host: String): Long {
        if (host.isBlank()) return -1L
        return try {
            val process = ProcessBuilder("ping", "-c", "1", "-W", "2", host).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()
            Regex("""time[=<]([0-9.]+)""").find(output)?.groupValues?.get(1)?.toDoubleOrNull()
                ?.let { Math.max(1L, Math.round(it)) } ?: -1L
        } catch (_: Exception) {
            -1L
        }
    }

    private fun startTcping(guid: String): Long {
        val retFailure = -1L

        val config = MmkvManager.decodeServerConfig(guid) ?: return retFailure
        if (config.configType == EConfigType.OPENVPN && (config.ovpnProto == "udp" || config.ovpnProto == "both" || (config.ovpnProto != "tcp" && config.mode == "udp"))) {
            return OpenVpnProbe.measure(config)
        }
        if (!config.configType.isComplexType()
            && config.configType != EConfigType.HYSTERIA2
            && config.configType != EConfigType.WIREGUARD
            && !(config.configType == EConfigType.OPENVPN && (config.ovpnProto == "udp" || config.ovpnProto == "both" || (config.ovpnProto != "tcp" && config.mode == "udp")))
            && config.alpn?.split(',')?.all { it.trim().startsWith("h3") } != true
            && config.server.isNotNullEmpty()
            && config.serverPort?.toIntOrNull() != null
        ) {
            val url = config.server.orEmpty()
            val port = config.serverPort.orEmpty().toInt()
            val tcpTime = SpeedtestManager.socketConnectTime(url, port, 1000)

            return tcpTime
        }

        return retFailure
    }
}
