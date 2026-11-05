package com.v2ray.ang

import android.app.Application
import android.content.Context
import androidx.core.content.ContextCompat
import androidx.work.Configuration
import androidx.work.WorkManager
import com.v2ray.ang.AppConfig.ANG_PACKAGE
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.ui.compose.ThemeManager

class AngApplication : Application() {
    companion object {
        lateinit var application: AngApplication
    }

    /**
     * Attaches the base context to the application.
     * @param base The base context.
     */
    override fun attachBaseContext(base: Context?) {
        super.attachBaseContext(base?.let(ContextCompat::getContextForLanguage))
        application = this
    }

    private val workManagerConfiguration: Configuration = Configuration.Builder()
        .setDefaultProcessName("${ANG_PACKAGE}:bg")
        .build()

    /**
     * Initializes the application.
     */
    override fun onCreate() {
        super.onCreate()

        MmkvManager.initialize(this)

        AppLocaleManager.initialize(this)

        // Initialize WorkManager with the custom configuration
        WorkManager.initialize(this, workManagerConfiguration)

        // Ensure critical preference defaults are present in MMKV early
        SettingsManager.initApp(this)

        // Initialize theme state from MMKV
        ThemeManager.refresh()

        startUiWatchdog()
    }

    /**
     * Diagnostics for "the app froze": while the app is in the foreground process, a background thread pings the
     * main thread; when it does not answer for 4 s, the main thread's stack (the code it is stuck in) is written to
     * the log under the tag `EGN-ANR`, so it shows up on the logs screen.
     */
    private fun startUiWatchdog() {
        val main = android.os.Handler(android.os.Looper.getMainLooper())
        val mainThread = android.os.Looper.getMainLooper().thread
        Thread({
            var reported = false
            while (true) {
                val answered = java.util.concurrent.atomic.AtomicBoolean(false)
                main.post { answered.set(true) }
                try {
                    Thread.sleep(4000)
                } catch (_: InterruptedException) {
                    return@Thread
                }
                if (answered.get()) {
                    reported = false
                } else if (!reported) {
                    reported = true
                    val stack = mainThread.stackTrace.joinToString("\n") { "    at $it" }
                    android.util.Log.e("EGN-ANR", "UI thread blocked for 4s+:\n$stack")
                }
            }
        }, "egn-ui-watchdog").apply { isDaemon = true }.start()
    }
}
