package com.v2ray.ang.ui.main

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.v2ray.ang.R
import com.v2ray.ang.dto.TrafficSnapshot
import com.v2ray.ang.extension.toSpeedString
import com.v2ray.ang.extension.toTrafficString
import kotlinx.coroutines.delay

/** `HH:MM:SS`; hours keep counting past 24. Negative input (clock changes) is shown as zero. */
internal fun formatConnectionDuration(elapsedMs: Long): String {
    val totalSeconds = (elapsedMs.coerceAtLeast(0L)) / 1000L
    val hours = totalSeconds / 3600L
    val minutes = (totalSeconds % 3600L) / 60L
    val seconds = totalSeconds % 60L
    return "%02d:%02d:%02d".format(hours, minutes, seconds)
}

/**
 * Live session card: download/upload speed, data used this session and time connected.
 * The clock ticks locally every second; the numbers come from the service about once a second.
 */
@Composable
fun ConnectionStatsCard(stats: TrafficSnapshot, modifier: Modifier = Modifier) {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(stats.connectedSinceMs) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            // one row-level node: TalkBack reads the whole card in order instead of eight stops
            .semantics(mergeDescendants = true) {},
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            StatCell(stringResource(R.string.stats_download), stats.downSpeed.toSpeedString())
            StatCell(stringResource(R.string.stats_upload), stats.upSpeed.toSpeedString())
            StatCell(
                stringResource(R.string.stats_session_usage),
                (stats.totalDown + stats.totalUp).toTrafficString()
            )
            StatCell(
                stringResource(R.string.stats_duration),
                formatConnectionDuration(now - stats.connectedSinceMs)
            )
        }
    }
}

@Composable
private fun StatCell(label: String, value: String) {
    Column {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onPrimaryContainer,
        )
    }
}
