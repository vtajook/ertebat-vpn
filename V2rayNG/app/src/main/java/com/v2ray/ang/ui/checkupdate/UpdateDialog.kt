package com.v2ray.ang.ui.checkupdate

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.dto.CheckUpdateResult
import com.v2ray.ang.handler.ApkInstaller
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.UpdateCheckerManager
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.launch

/** "New version" dialog: downloads the APK inside the app and starts the system installer. */
@Composable
fun UpdateDialog(result: CheckUpdateResult, onDismiss: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var downloading by remember { mutableStateOf(false) }
    var percent by remember { mutableIntStateOf(-1) }
    var failed by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = { if (!downloading) onDismiss() },
        title = { Text(stringResource(R.string.update_new_version_found, result.latestVersion ?: "")) },
        text = {
            Column {
                val scrollState = rememberScrollState()
                Text(
                    text = result.releaseNotes.orEmpty(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .verticalScroll(scrollState)
                )
                if (downloading) {
                    if (percent in 0..100) {
                        LinearProgressIndicator(progress = { percent / 100f }, modifier = Modifier.fillMaxWidth().padding(top = 12.dp))
                    } else {
                        LinearProgressIndicator(modifier = Modifier.fillMaxWidth().padding(top = 12.dp))
                    }
                }
                if (failed) {
                    Text(
                        text = stringResource(R.string.toast_failure),
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !downloading && result.downloadUrl != null,
                onClick = {
                    val url = result.downloadUrl ?: return@TextButton
                    failed = false
                    downloading = true
                    scope.launch {
                        try {
                            val apk = ApkInstaller.download(context, url) { percent = it }
                            downloading = false
                            ApkInstaller.install(context, apk)
                            onDismiss()
                        } catch (t: Throwable) {
                            LogUtil.e(AppConfig.TAG, "Update download failed", t)
                            downloading = false
                            failed = true
                        }
                    }
                }
            ) { Text(stringResource(R.string.update_now)) }
        },
        dismissButton = {
            TextButton(enabled = !downloading, onClick = onDismiss) { Text(stringResource(R.string.action_cancel)) }
        },
        containerColor = MaterialTheme.colorScheme.surface
    )
}

private const val KEY_LAST_AUTO_CHECK = "egn_last_update_check"
private const val AUTO_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000L

/** Checks GitHub for a newer release when the main screen opens (at most every 6 hours) and offers it. */
@Composable
fun AutoUpdatePrompt() {
    var result by remember { mutableStateOf<CheckUpdateResult?>(null) }
    LaunchedEffect(Unit) {
        val last = MmkvManager.decodeSettingsString(KEY_LAST_AUTO_CHECK, "0")?.toLongOrNull() ?: 0L
        if (System.currentTimeMillis() - last < AUTO_CHECK_INTERVAL_MS) return@LaunchedEffect
        try {
            val r = UpdateCheckerManager.checkForUpdate()
            MmkvManager.encodeSettings(KEY_LAST_AUTO_CHECK, System.currentTimeMillis().toString())
            if (r.hasUpdate) result = r
        } catch (t: Throwable) {
            LogUtil.w(AppConfig.TAG, "Automatic update check failed: ${t.message}")
        }
    }
    result?.let { UpdateDialog(it) { result = null } }
}
