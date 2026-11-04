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
import com.v2ray.ang.core.ovpn.OpenVpnEngine
import com.v2ray.ang.dto.TrafficSnapshot
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
 * VPN service for OpenVPN profiles. It runs next to (never together with) [CoreVpnService] in the same
 * `:daemon` process and speaks the same broadcast protocol with the main screen: register / stop /
 * restart requests come in, start / stop / running state and [TrafficSnapshot] go out.
 */
@SuppressLint("VpnServicePolicy")
class OpenVpnService : VpnService() {

    private var engine: OpenVpnEngine? = null
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
                    this@OpenVpnService,
                    if (connected) AppConfig.MSG_STATE_RUNNING else AppConfig.MSG_STATE_NOT_RUNNING,
                    ""
                )

                AppConfig.MSG_STATE_STOP -> stopVpn()

                AppConfig.MSG_STATE_RESTART -> {
                    if (isOrderedBroadcast) resultCode = Activity.RESULT_OK
                    stopVpn()
                    android.os.Handler(mainLooper).postDelayed({
                        LauncherManager.startService(this@OpenVpnService)
                    }, 800L)
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

        if (config == null || config.ovpnConfig.isNullOrBlank()) {
            fail("OpenVPN profile is empty")
            return START_NOT_STICKY
        }
        if (prepare(this) != null) {
            fail("VPN permission not granted")
            return START_NOT_STICKY
        }
        if (worker != null) {
            LogUtil.w(AppConfig.TAG, "OpenVPN: start already in progress")
            return START_NOT_STICKY
        }

        profile = config
        stopping.set(false)
        worker = Thread({ runSession(config) }, "ovpn-session").also { it.start() }
        return START_NOT_STICKY
    }

    private fun runSession(config: ProfileItem) {
        val listener = object : OpenVpnEngine.Listener {
            override fun onState(name: String, info: String) {
                LogUtil.i(AppConfig.TAG, "OpenVPN event: $name $info")
                when (name) {
                    "CONNECTED" -> onConnected()
                    "AUTH_FAILED" -> {
                        fail("AUTH_FAILED: $info".trim(':', ' '))
                    }
                    "CONNECTION_TIMEOUT", "CERT_VERIFY_FAIL", "TLS_VERSION_MIN", "CLIENT_HALT", "TUN_SETUP_FAILED",
                    "PROXY_NEED_CREDS", "NEED_CREDS", "DYNAMIC_CHALLENGE" -> fail("$name $info".trim())
                }
            }

            override fun onLog(line: String) {
                if (line.isNotBlank()) LogUtil.d(AppConfig.TAG, "OpenVPN: $line")
            }
        }

        val e = OpenVpnEngine(this, listener)
        engine = e
        try {
            val error = e.configure(config.ovpnConfig.orEmpty(), config.username, config.password)
            if (error != null) {
                fail(error)
                return
            }
            val result = e.run()
            if (!stopping.get() && result != null) fail(result)
        } catch (t: Throwable) {
            LogUtil.e(AppConfig.TAG, "OpenVPN session crashed", t)
            fail(t.message ?: t.javaClass.simpleName)
        } finally {
            if (!stopping.get()) android.os.Handler(mainLooper).post { stopVpn() }
        }
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
        LogUtil.e(AppConfig.TAG, "OpenVPN failure: $message")
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
                    LogUtil.w(AppConfig.TAG, "OpenVPN stats: ${t.message}")
                }
            }
        }, "ovpn-stats").also { it.isDaemon = true; it.start() }
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
        Thread({ runCatching { e?.stop() } }, "ovpn-stop").start()
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
        stopping.set(true)
        connected = false
        statsThread?.interrupt()
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
