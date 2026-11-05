package com.v2ray.ang.handler

import android.os.Build
import com.v2ray.ang.AppConfig
import com.v2ray.ang.BuildConfig
import com.v2ray.ang.dto.CheckUpdateResult
import com.v2ray.ang.dto.GitHubRelease
import com.v2ray.ang.dto.UrlContentRequest
import com.v2ray.ang.util.HttpUtil
import com.v2ray.ang.util.JsonUtil
import com.v2ray.ang.util.LogUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object UpdateCheckerManager {
    /**
     * Looks at the newest GitHub release of the app. All builds are published as pre-releases, so the release
     * list (newest first) is read instead of "latest". The installed version is the release tag the build was
     * made for ([BuildConfig.RELEASE_TAG]); a local "dev" build never offers an update.
     */
    suspend fun checkForUpdate(): CheckUpdateResult = withContext(Dispatchers.IO) {
        val url = AppConfig.APP_API_URL

        var response = HttpUtil.getUrlContent(UrlContentRequest(url = url, timeout = 5000))
        if (response.isNullOrEmpty()) {
            // through the local proxy when the VPN is running with it
            response = HttpUtil.getUrlContent(
                UrlContentRequest(
                    url = url,
                    timeout = 5000,
                    httpPort = SettingsManager.getHttpPort(),
                    proxyUsername = SettingsManager.getSocksUsername(),
                    proxyPassword = SettingsManager.getSocksPassword()
                )
            ) ?: throw IllegalStateException("Failed to get response")
        }

        // Newest release that has files of THIS brand: a test release made for one brand only is ignored by the others.
        val prefix = BuildConfig.APK_PREFIX + "_"
        val latestRelease = JsonUtil.fromJsonSafe(response, Array<GitHubRelease>::class.java)
            ?.firstOrNull { r -> r.assets.any { it.name.startsWith(prefix) && it.name.endsWith(".apk") } }
            ?: return@withContext CheckUpdateResult(hasUpdate = false)

        val latestVersion = latestRelease.tagName.removePrefix("v")
        val current = BuildConfig.RELEASE_TAG.removePrefix("v")
        LogUtil.i(AppConfig.TAG, "Latest release: $latestVersion (installed: $current)")

        return@withContext if (versionParts(current) != null && compareVersions(latestVersion, current) > 0) {
            CheckUpdateResult(
                hasUpdate = true,
                latestVersion = latestVersion,
                releaseNotes = latestRelease.body,
                downloadUrl = getDownloadUrl(latestRelease, Build.SUPPORTED_ABIS[0]),
                isPreRelease = latestRelease.prerelease
            )
        } else {
            CheckUpdateResult(hasUpdate = false)
        }
    }

    /** "0.8.2-test" -> [0, 8, 2]; null when the text has no leading version number (e.g. "dev"). */
    private fun versionParts(version: String): List<Int>? {
        val m = Regex("^[0-9]+(\\.[0-9]+)*").find(version.trim()) ?: return null
        return m.value.split(".").map { it.toInt() }
    }

    private fun compareVersions(version1: String, version2: String): Int {
        val v1 = versionParts(version1) ?: return 0
        val v2 = versionParts(version2) ?: return 0
        for (i in 0 until maxOf(v1.size, v2.size)) {
            val num1 = v1.getOrElse(i) { 0 }
            val num2 = v2.getOrElse(i) { 0 }
            if (num1 != num2) return num1 - num2
        }
        return 0
    }

    /** The APK of this brand for the phone's CPU, falling back to the universal one. */
    private fun getDownloadUrl(release: GitHubRelease, abi: String): String {
        val mine = release.assets.filter { it.name.startsWith(BuildConfig.APK_PREFIX + "_") && it.name.endsWith(".apk") }
        val asset = mine.firstOrNull { it.name.contains(abi, true) }
            ?: mine.firstOrNull { it.name.contains("universal", true) }
        return asset?.browserDownloadUrl ?: throw IllegalStateException("No compatible APK found")
    }
}
