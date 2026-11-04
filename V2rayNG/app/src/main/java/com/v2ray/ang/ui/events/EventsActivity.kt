package com.v2ray.ang.ui.events

import android.content.Intent
import androidx.activity.viewModels
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.v2ray.ang.R
import com.v2ray.ang.handler.EventLog
import com.v2ray.ang.ui.base.BaseComponentActivity
import com.v2ray.ang.ui.compose.AppTopBar
import com.v2ray.ang.ui.compose.colorInfo
import com.v2ray.ang.ui.compose.statusError
import com.v2ray.ang.ui.compose.statusSuccess
import com.v2ray.ang.ui.logcat.LogcatActivity
import java.text.DateFormat
import java.util.Date

/** Connection history: when a profile connected, disconnected or failed, with the reason. */
class EventsActivity : BaseComponentActivity() {
    private val viewModel: EventsViewModel by viewModels()

    override fun onResume() {
        super.onResume()
        viewModel.load()
    }

    @Composable
    override fun ScreenContent() {
        EventsScreen(
            viewModel = viewModel,
            onBackClick = { finish() },
            onOpenTechnicalLog = { startActivity(Intent(this, LogcatActivity::class.java)) },
        )
    }
}

@Composable
private fun EventsScreen(viewModel: EventsViewModel, onBackClick: () -> Unit, onOpenTechnicalLog: () -> Unit) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    var confirmClear by remember { mutableStateOf(false) }
    val shown = applyFilter(state.entries, state.filter)

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            title = { Text(stringResource(R.string.egn_events_clear_title)) },
            text = { Text(stringResource(R.string.egn_events_clear_message)) },
            confirmButton = {
                TextButton(onClick = { confirmClear = false; viewModel.clear() }) {
                    Text(stringResource(R.string.egn_events_clear), color = MaterialTheme.colorScheme.primary)
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text(stringResource(R.string.action_cancel)) }
            },
        )
    }

    Scaffold(
        topBar = {
            AppTopBar(
                title = stringResource(R.string.egn_nav_logs),
                onBackClick = onBackClick,
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(painterResource(R.drawable.ic_arrow_back_24dp), contentDescription = stringResource(R.string.acc_back))
                    }
                },
                actions = {
                    IconButton(onClick = onOpenTechnicalLog) {
                        Icon(painterResource(R.drawable.ic_logcat_24dp), contentDescription = stringResource(R.string.egn_events_technical))
                    }
                    IconButton(onClick = { confirmClear = true }) {
                        Icon(painterResource(R.drawable.ic_delete_24dp), contentDescription = stringResource(R.string.egn_events_clear))
                    }
                }
            )
        }
    ) { innerPadding ->
        Column(Modifier.fillMaxSize().padding(innerPadding)) {
            LazyRow(
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                items(EventFilter.entries.toList()) { f ->
                    val label = stringResource(
                        when (f) {
                            EventFilter.All -> R.string.egn_events_filter_all
                            EventFilter.Success -> R.string.egn_events_filter_success
                            EventFilter.Error -> R.string.egn_events_filter_error
                            EventFilter.Info -> R.string.egn_events_filter_info
                        }
                    )
                    FilterChip(
                        selected = state.filter == f,
                        onClick = { viewModel.setFilter(f) },
                        label = { Text(label) },
                    )
                }
            }
            if (shown.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        stringResource(R.string.egn_events_empty),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center,
                    )
                }
            } else {
                LazyColumn(
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 4.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.fillMaxSize()
                ) {
                    items(shown, key = { "${it.timeMs}-${it.kind}-${it.detail.hashCode()}" }) { entry ->
                        EventRow(entry)
                    }
                }
            }
        }
    }
}

@Composable
private fun EventRow(entry: EventLog.Entry) {
    val kind = filterOf(entry.kind)
    val accent: Color = when (kind) {
        EventFilter.Success -> statusSuccess()
        EventFilter.Error -> statusError()
        else -> colorInfo
    }
    val glyph = when (kind) {
        EventFilter.Success -> "✓"
        EventFilter.Error -> "✕"
        else -> "i"
    }
    val title = stringResource(
        when (entry.kind) {
            EventLog.KIND_CONNECTED -> R.string.egn_event_connected
            EventLog.KIND_FAILED -> R.string.egn_event_failed
            else -> R.string.egn_event_disconnected
        }
    )
    val shape = RoundedCornerShape(14.dp)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(shape)
            .background(MaterialTheme.colorScheme.surfaceContainer)
            .border(1.dp, MaterialTheme.colorScheme.outlineVariant, shape)
            .padding(12.dp)
            .semantics(mergeDescendants = true) {},
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier.size(40.dp).clip(CircleShape).background(accent.copy(alpha = 0.15f)),
            contentAlignment = Alignment.Center
        ) {
            Text(glyph, color = accent, fontSize = 18.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(title, color = accent, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyLarge)
            if (entry.detail.isNotBlank()) {
                Text(
                    entry.detail,
                    style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Content),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Spacer(Modifier.width(8.dp))
        Text(
            DateFormat.getTimeInstance(DateFormat.SHORT).format(Date(entry.timeMs)),
            style = MaterialTheme.typography.bodySmall.copy(textDirection = TextDirection.Ltr),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}
