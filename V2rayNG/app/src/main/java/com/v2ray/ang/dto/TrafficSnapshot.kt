package com.v2ray.ang.dto

import java.io.Serializable

/**
 * Live traffic numbers of the running session, sent from the service process to the main screen.
 * Only traffic that goes through the proxy outbound is counted (that is what a customer's quota is).
 *
 * @property upSpeed upload speed in bytes per second
 * @property downSpeed download speed in bytes per second
 * @property totalUp bytes uploaded since this session started
 * @property totalDown bytes downloaded since this session started
 * @property connectedSinceMs wall-clock time (epoch millis) at which the session started
 */
data class TrafficSnapshot(
    val upSpeed: Long,
    val downSpeed: Long,
    val totalUp: Long,
    val totalDown: Long,
    val connectedSinceMs: Long,
) : Serializable
