package com.v2ray.ang.ui.main

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.v2ray.ang.R
import com.v2ray.ang.dto.TrafficSnapshot
import com.v2ray.ang.extension.toSpeedString
import com.v2ray.ang.ui.compose.colorSuccess
import com.v2ray.ang.ui.compose.pingColor
import kotlinx.coroutines.delay

/** Small top bar for the home and ping tabs: menu button, title, settings button. */
@Composable
fun EgnTopBar(title: String, onMenuClick: () -> Unit, onSettingsClick: (() -> Unit)?) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp, vertical = 4.dp)
            .height(56.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        IconButton(onClick = onMenuClick) {
            Icon(painterResource(R.drawable.ic_menu_24dp), contentDescription = stringResource(R.string.acc_open_menu))
        }
        Text(
            text = title,
            modifier = Modifier.weight(1f),
            textAlign = TextAlign.Center,
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Medium,
        )
        if (onSettingsClick != null) {
            IconButton(onClick = onSettingsClick) {
                Icon(painterResource(R.drawable.ic_settings_24dp), contentDescription = stringResource(R.string.title_settings))
            }
        } else {
            Spacer(Modifier.size(48.dp))
        }
    }
}

@Composable
internal fun HomeContent(
    uiState: MainUiState,
    statusText: String,
    onToggle: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val isRunning = uiState.isRunning
    val stats = if (isRunning) uiState.stats else null

    // latest measured delay of the running profile, kept while the status line shows other messages
    var lastPing by remember { mutableLongStateOf(-1L) }
    val status = uiState.status
    LaunchedEffect(status) {
        if (status is MainStatus.ConnectionTest && status.result.delayMillis >= 0) {
            lastPing = status.result.delayMillis
        }
    }
    LaunchedEffect(isRunning) { if (!isRunning) lastPing = -1L }

    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(isRunning, stats?.connectedSinceMs) {
        while (isRunning) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }

    val history = remember { mutableStateListOf<Long>() }
    LaunchedEffect(isRunning) { if (!isRunning) history.clear() }
    LaunchedEffect(stats?.downSpeed, stats?.upSpeed) {
        val s = stats ?: return@LaunchedEffect
        history.add(s.downSpeed + s.upSpeed)
        while (history.size > 40) history.removeAt(0)
    }

    val stateColor = if (isRunning) colorSuccess else MaterialTheme.colorScheme.onSurfaceVariant
    val stateText = stringResource(if (isRunning) R.string.egn_home_connected else R.string.egn_home_disconnected)

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(8.dp))
        Image(
            painter = painterResource(R.drawable.egn_logo),
            contentDescription = null,
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .size(190.dp)
                .clip(CircleShape)
                .border(2.dp, MaterialTheme.colorScheme.primary.copy(alpha = if (isRunning) 0.9f else 0.45f), CircleShape)
        )
        Spacer(Modifier.height(14.dp))
        Text(
            text = stateText,
            color = stateColor,
            fontSize = 28.sp,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = statusText,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = onToggle,
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = Color.White,
            ),
        ) {
            Icon(
                painter = painterResource(if (isRunning) R.drawable.ic_stop_24dp else R.drawable.ic_play_24dp),
                contentDescription = null,
                modifier = Modifier.size(22.dp),
            )
            Spacer(Modifier.width(10.dp))
            Text(
                text = stringResource(if (isRunning) R.string.egn_home_disconnect else R.string.egn_home_connect),
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.height(16.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(
                label = stringResource(R.string.egn_home_ping),
                value = if (lastPing >= 0) stringResource(R.string.server_test_delay_value, lastPing) else "—",
                valueColor = if (lastPing >= 0) pingColor(lastPing) else MaterialTheme.colorScheme.onSurface,
            )
            StatTile(
                label = stringResource(R.string.stats_download),
                value = stats?.downSpeed?.toSpeedString() ?: "—",
            )
        }
        Spacer(Modifier.height(12.dp))
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            StatTile(
                label = stringResource(R.string.stats_upload),
                value = stats?.upSpeed?.toSpeedString() ?: "—",
            )
            StatTile(
                label = stringResource(R.string.stats_duration),
                value = if (stats != null) formatConnectionDuration(now - stats.connectedSinceMs) else "—",
            )
        }
        Spacer(Modifier.height(16.dp))
        SpeedChart(history, Modifier.fillMaxWidth().height(70.dp))
        Spacer(Modifier.height(16.dp))
    }
}

@Composable
private fun RowScope.StatTile(
    label: String,
    value: String,
    valueColor: Color = MaterialTheme.colorScheme.onSurface,
) {
    Column(
        modifier = Modifier
            .weight(1f)
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(16.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp)
            .semantics(mergeDescendants = true) {},
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
        Text(
            value,
            style = MaterialTheme.typography.titleMedium.copy(textDirection = TextDirection.Ltr),
            fontWeight = FontWeight.Bold,
            color = valueColor,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}

@Composable
private fun SpeedChart(samples: List<Long>, modifier: Modifier = Modifier) {
    val barColor = colorSuccess
    val emptyColor = MaterialTheme.colorScheme.outlineVariant
    Canvas(modifier = modifier) {
        val slots = 40
        val gap = 3.dp.toPx()
        val barW = (size.width - gap * (slots - 1)) / slots
        val max = (samples.maxOrNull() ?: 0L).coerceAtLeast(1L).toFloat()
        val offset = slots - samples.size
        for (i in 0 until slots) {
            val idx = i - offset
            val value = if (idx >= 0) samples[idx] else -1L
            val h = if (value < 0) 3.dp.toPx() else (value / max * size.height).coerceAtLeast(3.dp.toPx())
            drawRoundRect(
                color = if (value < 0) emptyColor else barColor,
                topLeft = Offset(i * (barW + gap), size.height - h),
                size = Size(barW, h),
                cornerRadius = CornerRadius(2.dp.toPx()),
            )
        }
    }
}

@Composable
internal fun PingContent(
    rows: List<ServerRowUiModel>,
    selectedGuid: String?,
    isTesting: Boolean,
    onStart: () -> Unit,
    onStop: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val selected = rows.firstOrNull { it.guid == selectedGuid }
    val delay = selected?.testDelayMillis ?: 0L
    val ringColor = if (delay > 0L) pingColor(delay) else MaterialTheme.colorScheme.primary
    val sorted = rows.sortedWith(compareBy({ if (it.testDelayMillis > 0) 0 else 1 }, { it.testDelayMillis }))

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Spacer(Modifier.height(8.dp))
        Box(
            modifier = Modifier
                .size(190.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceContainer)
                .border(6.dp, ringColor.copy(alpha = 0.85f), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = if (delay > 0L) stringResource(R.string.server_test_delay_value, delay) else "—",
                    style = MaterialTheme.typography.headlineMedium.copy(textDirection = TextDirection.Ltr),
                    fontWeight = FontWeight.Bold,
                    color = if (delay > 0L) ringColor else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(
                    text = stringResource(R.string.egn_ping_latency),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.height(16.dp))
        Button(
            onClick = if (isTesting) onStop else onStart,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp),
            shape = RoundedCornerShape(16.dp),
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.primary,
                contentColor = Color.White,
            ),
        ) {
            Text(
                text = stringResource(if (isTesting) R.string.egn_ping_stop else R.string.egn_ping_start),
                fontSize = 17.sp,
                fontWeight = FontWeight.Bold,
            )
        }
        Spacer(Modifier.height(16.dp))
        Text(
            text = stringResource(R.string.egn_ping_results),
            modifier = Modifier.fillMaxWidth(),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Spacer(Modifier.height(6.dp))
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(bottom = 12.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            items(sorted, key = { it.guid }) { row ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainer)
                        .padding(horizontal = 14.dp, vertical = 12.dp)
                        .semantics(mergeDescendants = true) {},
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        row.remarks,
                        modifier = Modifier.weight(1f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                    val d = row.testDelayMillis
                    Text(
                        text = when {
                            d == 0L -> ""
                            d < 0L -> "—"
                            else -> stringResource(R.string.server_test_delay_value, d)
                        },
                        style = MaterialTheme.typography.bodyMedium.copy(textDirection = TextDirection.Ltr),
                        fontWeight = FontWeight.Bold,
                        color = pingColor(d),
                    )
                    Spacer(Modifier.width(8.dp))
                    Box(
                        Modifier
                            .size(10.dp)
                            .clip(CircleShape)
                            .background(if (d == 0L) MaterialTheme.colorScheme.outlineVariant else pingColor(d))
                    )
                }
            }
        }
    }
}
