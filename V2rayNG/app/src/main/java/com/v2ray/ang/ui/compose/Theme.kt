package com.v2ray.ang.ui.compose

import android.app.Activity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import com.v2ray.ang.R
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.v2ray.ang.AppConfig
import com.v2ray.ang.handler.MmkvManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

// EGN VPN "Dark Cyber Red" design tokens
val colorBackground = Color(0xFF0A0B0F)
val colorSurface = Color(0xFF121720)
val colorSurfaceElevated = Color(0xFF1A222D)
val colorDivider = Color(0xFF26313D)
val colorTextPrimary = Color(0xFFF4F7FB)
val colorTextSecondary = Color(0xFFAAB4C2)
val colorTextMuted = Color(0xFF778391)
val colorBrand = Color(0xFFFF2638)
val colorBrandBright = Color(0xFFFF4050)
val colorSuccess = Color(0xFF00D68F)
val colorWarning = Color(0xFFFFB547)
val colorError = Color(0xFFFF5964)
val colorInfo = Color(0xFF35BDF2)
val colorNoResponse = Color(0xFF8993A1)

private val DarkColor = darkColorScheme(
    primary = colorBrand,
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF3A0E14),
    onPrimaryContainer = Color(0xFFFFD9DC),
    secondary = colorBrandBright,
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = colorSurfaceElevated,
    onSecondaryContainer = colorTextPrimary,
    tertiary = colorSuccess,
    onTertiary = Color(0xFF00382A),
    tertiaryContainer = Color(0xFF0B3A2C),
    onTertiaryContainer = Color(0xFFB7F5DF),
    error = colorError,
    errorContainer = Color(0xFF3A1015),
    onError = Color(0xFFFFFFFF),
    onErrorContainer = Color(0xFFFFD9DC),
    background = colorBackground,
    onBackground = colorTextPrimary,
    surface = Color(0xFF0E1218),
    onSurface = colorTextPrimary,
    surfaceVariant = colorSurfaceElevated,
    onSurfaceVariant = colorTextSecondary,
    outline = colorTextMuted,
    outlineVariant = colorDivider,
    inverseSurface = colorTextPrimary,
    inverseOnSurface = colorBackground,
    inversePrimary = colorBrand,
    scrim = Color(0xFF000000),
    surfaceTint = colorBrand,
    surfaceContainerLowest = colorBackground,
    surfaceContainerLow = Color(0xFF0E1218),
    surfaceContainer = colorSurface,
    surfaceContainerHigh = colorSurfaceElevated,
    surfaceContainerHighest = Color(0xFF212B38),
)

private val LightColor = lightColorScheme(
    primary = Color(0xFFE01E30),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFFFDADD),
    onPrimaryContainer = Color(0xFF410006),
    secondary = Color(0xFFC21A2A),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFE9EDF2),
    onSecondaryContainer = Color(0xFF0A0B0F),
    tertiary = Color(0xFF008F5F),
    onTertiary = Color(0xFFFFFFFF),
    tertiaryContainer = Color(0xFFB7F5DF),
    onTertiaryContainer = Color(0xFF00201A),
    error = Color(0xFFD63040),
    errorContainer = Color(0xFFFFDAD6),
    onError = Color(0xFFFFFFFF),
    onErrorContainer = Color(0xFF410002),
    background = Color(0xFFF5F6F8),
    onBackground = Color(0xFF0A0B0F),
    surface = Color(0xFFF5F6F8),
    onSurface = Color(0xFF0A0B0F),
    surfaceVariant = Color(0xFFE6EAF0),
    onSurfaceVariant = Color(0xFF4A5565),
    outline = Color(0xFF778391),
    outlineVariant = Color(0xFFD5DBE3),
    inverseSurface = Color(0xFF121720),
    inverseOnSurface = Color(0xFFF4F7FB),
    inversePrimary = Color(0xFFFF4050),
    scrim = Color(0xFF000000),
    surfaceTint = Color(0xFFE01E30),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFFFFFFF),
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFEEF1F5),
    surfaceContainerHighest = Color(0xFFE6EAF0),
)

// Semantic Colors
val colorPing = colorSuccess
val colorPingRed = colorError
val colorConfigType = colorInfo
val colorFabActive = colorBrand
val colorFabInactiveLight = colorDivider
val colorFabInactiveDark = colorDivider
val dividerColorLight = Color(0xFFD5DBE3)
val dividerColorDark = colorDivider

/** Colour of a delay value: 0-80 ms good, 81-150 ms medium, above that poor, negative = no answer. */
fun pingColor(delayMillis: Long): Color = when {
    delayMillis < 0L -> colorNoResponse
    delayMillis <= 80L -> colorSuccess
    delayMillis <= 150L -> colorWarning
    else -> colorError
}

private val Vazirmatn = FontFamily(
    Font(R.font.vazirmatn_regular, FontWeight.Normal),
    Font(R.font.vazirmatn_medium, FontWeight.Medium),
    Font(R.font.vazirmatn_bold, FontWeight.Bold),
)

private val AppTypography = Typography().let { t ->
    fun TextStyle.vz() = copy(fontFamily = Vazirmatn)
    Typography(
        displayLarge = t.displayLarge.vz(), displayMedium = t.displayMedium.vz(), displaySmall = t.displaySmall.vz(),
        headlineLarge = t.headlineLarge.vz(), headlineMedium = t.headlineMedium.vz(), headlineSmall = t.headlineSmall.vz(),
        titleLarge = t.titleLarge.vz(), titleMedium = t.titleMedium.vz(), titleSmall = t.titleSmall.vz(),
        bodyLarge = t.bodyLarge.vz(), bodyMedium = t.bodyMedium.vz(), bodySmall = t.bodySmall.vz(),
        labelLarge = t.labelLarge.vz(), labelMedium = t.labelMedium.vz(), labelSmall = t.labelSmall.vz(),
    )
}

// Toast Colors 85%
val toastNormalBgLight = Color(0xD9353A3E) // Dark Gray
val toastNormalBgDark = Color(0xD94A4F54) // Darker Gray
val toastSuccessBg = Color(0xD9388E3C) // Green
val toastErrorBg = Color(0xD9D50000) // Red
val toastInfoBg = Color(0xD93F51B5) // Indigo Blue
val toastIconCircleBg = Color(0x33FFFFFF) // Semi-transparent White
val toastTextColor = Color.White // White

object ThemeManager {
    private val _themeMode = MutableStateFlow(
        MmkvManager.decodeSettingsString(AppConfig.PREF_UI_MODE_NIGHT, "2") ?: "2"
    )
    val themeMode: StateFlow<String> = _themeMode.asStateFlow()

    private val _dynamicColorEnabled = MutableStateFlow(
        MmkvManager.decodeSettingsBool(AppConfig.PREF_DYNAMIC_COLOR, true)
    )
    val dynamicColorEnabled: StateFlow<Boolean> = _dynamicColorEnabled.asStateFlow()

    fun setThemeMode(mode: String) {
        MmkvManager.encodeSettings(AppConfig.PREF_UI_MODE_NIGHT, mode)
        _themeMode.value = mode
    }

    fun setDynamicColorEnabled(enabled: Boolean) {
        MmkvManager.encodeSettings(AppConfig.PREF_DYNAMIC_COLOR, enabled)
        _dynamicColorEnabled.value = enabled
    }

    fun refresh() {
        _themeMode.value =
            MmkvManager.decodeSettingsString(AppConfig.PREF_UI_MODE_NIGHT, "2") ?: "2"
        _dynamicColorEnabled.value =
            MmkvManager.decodeSettingsBool(AppConfig.PREF_DYNAMIC_COLOR, true)
    }
}

@Composable
fun resolveDarkTheme(): Boolean {
    val mode by ThemeManager.themeMode.collectAsState()
    // Dark Cyber Red is the default look; light (or following the system) can still be chosen in settings.
    return when (mode) {
        "1" -> false
        "0" -> isSystemInDarkTheme()
        else -> true
    }
}

val LocalDarkTheme = compositionLocalOf { false }

@Composable
fun AppTheme(
    darkTheme: Boolean = resolveDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColor else LightColor
    val snackbarController = rememberAppSnackbarController()

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val activity = view.context as? Activity ?: return@SideEffect
            val window = activity.window
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    CompositionLocalProvider(
        LocalDarkTheme provides darkTheme,
        LocalAppSnackbar provides snackbarController
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = AppTypography
        ) {
            Box(modifier = Modifier.fillMaxSize()) {
                AppSnackbarBridge(controller = snackbarController)
                content()
                AppSnackbarHost(hostState = snackbarController.hostState)
            }
        }
    }
}
