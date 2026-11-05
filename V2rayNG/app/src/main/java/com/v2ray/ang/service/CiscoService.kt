package com.v2ray.ang.service

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.StrictMode
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.R
import com.v2ray.ang.core.LauncherManager
import com.v2ray.ang.core.cisco.CiscoEngine
import com.v2ray.ang.core.cisco.OcNative
import com.v2ray.ang.dto.ConnectionTestResult
import com.v2ray.ang.dto.TrafficSnapshot
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.handler.SpeedtestManager
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.handler.AppLocaleManager
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.helper.MessageHelper
import com.v2ray.ang.helper.NotificationHelper
import com.v2ray.ang.ui.main.MainActivity
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import java.util.concurrent.atomic.AtomicBoolean

/**
 * VPN service for Cisco AnyConnect profiles. It runs next to (never together with) [CoreVpnService] in the same
 * `:daemon` process and speaks the same broadcast protocol with the main screen: register / stop /
 * restart requests come in, start / stop / running state and [TrafficSnapshot] go out.
 */
@SuppressLint("VpnServicePolicy")
class CiscoService : VpnService() {

    private var engine: CiscoEngine? = null
    private var worker: Thread? = null
    private var statsThread: Thread? = null
    private val stopping = AtomicBoolean(false)

    @Volatile
    private var connected = false

    @Volatile
    private var sessionStartMs = 0L

    private var profile: ProfileItem? = null
    private var receiverRegistered = false
    private var notificationBuilder: NotificationCompat.Builder? = null

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            when (intent?.getIntExtra("key", 0)) {
                AppConfig.MSG_REGISTER_CLIENT -> MessageHelper.sendMsg2UI(
                    this@CiscoService,
                    if (connected) AppConfig.MSG_STATE_RUNNING else AppConfig.MSG_STATE_NOT_RUNNING,
                    ""
                )

                AppConfig.MSG_STATE_STOP -> stopVpn()

                AppConfig.MSG_MEASURE_DELAY -> {
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK
                    measureDelay(intent.getStringExtra("content").orEmpty())
                }

                AppConfig.MSG_STATE_RESTART -> {
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK
                    stopVpn()
                    android.os.Handler(mainLooper).postDelayed({
                        LauncherManager.startService(this@CiscoService)
                    }, 1200L)
                }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        StrictMode.setThreadPolicy(StrictMode.ThreadPolicy.Builder().permitAll().build())
        ContextCompat.registerReceiver(
            this, receiver, IntentFilter(AppConfig.BROADCAST_ACTION_SERVICE), Utils.receiverFlags()
        )
        receiverRegistered = true
    }

    override fun attachBaseContext(newBase: Context?) {
        super.attachBaseContext(newBase?.let(AppLocaleManager::localizedContext))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val guid = MmkvManager.getSelectServer()
        val config = guid?.let { MmkvManager.decodeServerConfig(it) }
        showNotification(config?.remarks)

        if (config == null || config.server.isNullOrBlank()) {
            fail("Cisco AnyConnect profile is incomplete")
            return START_NOT_STICKY
        }
        if (prepare(this) != null) {
            fail("VPN permission not granted")
            return START_NOT_STICKY
        }
        if (worker != null) {
            LogUtil.w(AppConfig.TAG, "Cisco AnyConnect: start already in progress")
            return START_NOT_STICKY
        }

        profile = config
        stopping.set(false)
        worker = Thread({ runSession(config) }, "cisco-session").also { it.start() }
        return START_NOT_STICKY
    }

    private fun runSession(config: ProfileItem) {
        val listener = object : CiscoEngine.Listener {
            override fun onConnected() {
                this@CiscoService.onConnected()
            }

            override fun onLog(line: String) {
                LogUtil.d(AppConfig.TAG, "Cisco: $line")
            }
        }
        try {
            val e = OcNative.newEngine(
                this, config.remarks, config.username.orEmpty(), config.password.orEmpty(), config.path, listener
            )
            engine = e
            val port = config.serverPort?.toIntOrNull() ?: 443
            val error = e.run(config.server.orEmpty(), port)
            if (!stopping.get() && error != null) fail(error)
        } catch (t: Throwable) {
            LogUtil.e(AppConfig.TAG, "Cisco AnyConnect session crashed", t)
            fail(t.message ?: t.javaClass.simpleName)
        } finally {
            worker = null
            if (!stopping.get()) android.os.Handler(mainLooper).post { stopVpn() }
        }
    }

    /**
     * Ends the native session. When it does not finish in a few seconds (libopenconnect stuck in a dead
     * connection) the VPN process is killed: that closes the tunnel and removes the VPN icon, which is
     * what a manual "force stop" did.
     */
    private fun terminateSession(e: CiscoEngine?, session: Thread?) {
        Thread({
            runCatching { e?.stop() }
            runCatching { session?.join(4000) }
            if (session?.isAlive == true) {
                LogUtil.e(AppConfig.TAG, "Cisco AnyConnect: session did not stop, restarting the VPN process")
                android.os.Process.killProcess(android.os.Process.myPid())
            }
        }, "cisco-stop").start()
    }

    /** "Test" while connected: time of a small HTTP request that goes through the tunnel. */
    private fun measureDelay(requestId: String) {
        if (!connected) {
            MessageHelper.sendMsg2UI(this, AppConfig.MSG_MEASURE_DELAY_CANCEL, "", requestId)
            return
        }
        Thread({
            var time = -1L
            var error = ""
            for (url in listOf(SettingsManager.getDelayTestUrl(), SettingsManager.getDelayTestUrl(true))) {
                try {
                    val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                    conn.connectTimeout = 8000
                    conn.readTimeout = 8000
                    conn.instanceFollowRedirects = false
                    conn.useCaches = false
                    val start = System.nanoTime()
                    val code = conn.responseCode
                    val elapsed = (System.nanoTime() - start) / 1_000_000
                    conn.disconnect()
                    if (code in 200..399) {
                        time = elapsed
                        error = ""
                        break
                    }
                    error = "HTTP $code"
                } catch (e: Exception) {
                    error = e.message ?: e.javaClass.simpleName
                }
            }
            val endpoint = if (time >= 0) SpeedtestManager.getRemoteIPInfo() else null
            val result = ConnectionTestResult(
                delayMillis = time,
                errorMessage = error,
                country = endpoint?.country,
                ipAddress = endpoint?.ipAddress,
            )
            MessageHelper.sendMsg2UI(
                this,
                if (connected) AppConfig.MSG_MEASURE_DELAY_RESULT else AppConfig.MSG_MEASURE_DELAY_CANCEL,
                if (connected) result else "",
                requestId
            )
        }, "cisco-delay").start()
    }

    private fun onConnected() {
        if (connected) return
        connected = true
        sessionStartMs = System.currentTimeMillis()
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_STATE_START_SUCCESS, "")
        startStats()
    }

    /** Reports a start / runtime failure to the main screen; the session is then torn down. */
    private fun fail(message: String) {
        if (stopping.get()) return
        LogUtil.e(AppConfig.TAG, "Cisco AnyConnect failure: $message")
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_STATE_START_FAILURE, message)
        android.os.Handler(mainLooper).post { stopVpn() }
    }

    private fun startStats() {
        val e = engine ?: return
        statsThread = Thread({
            var lastIn = 0L
            var lastOut = 0L
            var totalUp = 0L
            var totalDown = 0L
            var lastTime = System.currentTimeMillis()
            while (!stopping.get() && connected) {
                try {
                    Thread.sleep(1000)
                    val now = System.currentTimeMillis()
                    val bytesIn = e.bytesIn()
                    val bytesOut = e.bytesOut()
                    val seconds = ((now - lastTime) / 1000.0).coerceAtLeast(0.5)
                    val down = (bytesIn - lastIn).coerceAtLeast(0)
                    val up = (bytesOut - lastOut).coerceAtLeast(0)
                    lastIn = bytesIn
                    lastOut = bytesOut
                    lastTime = now
                    totalDown += down
                    totalUp += up
                    MessageHelper.sendMsg2UI(
                        this, AppConfig.MSG_STATS,
                        TrafficSnapshot(
                            upSpeed = (up / seconds).toLong(),
                            downSpeed = (down / seconds).toLong(),
                            totalUp = totalUp,
                            totalDown = totalDown,
                            connectedSinceMs = sessionStartMs,
                        )
                    )
                } catch (_: InterruptedException) {
                    break
                } catch (t: Throwable) {
                    LogUtil.w(AppConfig.TAG, "Cisco AnyConnect stats: ${t.message}")
                }
            }
        }, "cisco-stats").also { it.isDaemon = true; it.start() }
    }

    /** Stops the tunnel and the service. Safe to call more than once and from any thread. */
    private fun stopVpn() {
        if (!stopping.compareAndSet(false, true)) return
        connected = false
        val e = engine
        engine = null
        statsThread?.interrupt()
        statsThread = null
        // stop() ends the blocking connect() of the session thread; it can take a moment, so not here
        terminateSession(e, worker)
        MessageHelper.sendMsg2UI(this, AppConfig.MSG_STATE_STOP_SUCCESS, "")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        stopVpn()
    }

    override fun onDestroy() {
        if (receiverRegistered) {
            runCatching { unregisterReceiver(receiver) }
            receiverRegistered = false
        }
        val leftover = engine
        engine = null
        stopping.set(true)
        connected = false
        statsThread?.interrupt()
        if (leftover != null || worker != null) terminateSession(leftover, worker)
        super.onDestroy()
    }

    // ── notification ───────────────────────────────────────────────────────────────────────────

    private fun showNotification(title: String?) {
        val channelId = AppConfig.RAY_NG_CHANNEL_ID
        NotificationHelper.ensureNotificationChannel(
            context = this,
            channelId = channelId,
            channelNameRes = R.string.notification_channel_service,
            importance = NotificationManager.IMPORTANCE_LOW,
        )
        val flags = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), flags)
        val stopIntent = Intent(AppConfig.BROADCAST_ACTION_SERVICE).apply {
            `package` = AppConfig.ANG_PACKAGE
            putExtra("key", AppConfig.MSG_STATE_STOP)
        }
        val stop = PendingIntent.getBroadcast(this, 1, stopIntent, flags)

        val builder = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_stat_name)
            .setContentTitle(title ?: getString(R.string.app_name))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setShowWhen(false)
            .setOnlyAlertOnce(true)
            .setContentIntent(open)
            .addAction(R.drawable.ic_delete_24dp, getString(R.string.notification_action_stop_v2ray), stop)
        notificationBuilder = builder
        val notification: Notification = builder.build()
        startForeground(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val NOTIFICATION_ID = 1
    }
}
