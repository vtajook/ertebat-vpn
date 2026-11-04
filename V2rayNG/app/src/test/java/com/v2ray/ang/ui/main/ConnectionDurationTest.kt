package com.v2ray.ang.ui.main

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class ConnectionDurationTest {

    @Test
    fun zeroAndSubSecondShowZero() {
        assertEquals("00:00:00", formatConnectionDuration(0))
        assertEquals("00:00:00", formatConnectionDuration(999))
    }

    @Test
    fun formatsMinutesAndSeconds() {
        assertEquals("00:01:05", formatConnectionDuration(65_000))
    }

    @Test
    fun hoursKeepCountingPastADay() {
        assertEquals("25:00:01", formatConnectionDuration((25 * 3600 + 1) * 1000L))
    }

    @Test
    fun negativeElapsedIsClampedToZero() {
        assertEquals("00:00:00", formatConnectionDuration(-5_000))
    }
}
