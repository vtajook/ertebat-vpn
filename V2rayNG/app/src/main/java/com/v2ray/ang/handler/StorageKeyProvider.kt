package com.v2ray.ang.handler

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import com.v2ray.ang.AppConfig
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Provides the key that encrypts the on-device config storage (MMKV `cryptKey`).
 *
 * The storage key is random and never leaves the app in clear text: it is kept in a file under
 * `noBackupFilesDir`, encrypted with an AES-256-GCM key that lives in the Android Keystore (hardware
 * backed where the device supports it and not extractable). Copying the app's data directory to
 * another device therefore does not expose configs, passwords or links.
 *
 * The app runs in several processes (UI, daemon, tasks) that all open the same stores, so the first
 * creation of the key is serialised with a file lock to make sure every process gets the same key.
 */
object StorageKeyProvider {

    private const val TAG = AppConfig.TAG
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val WRAP_KEY_ALIAS = "egn_vpn_storage_wrap_key"
    private const val KEY_FILE = "egn_storage_key.bin"
    private const val LOCK_FILE = "egn_storage_key.lock"
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    // MMKV accepts at most 16 bytes of key material: 16 random characters from a 62-symbol alphabet.
    private const val KEY_LENGTH = 16
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

    @Volatile
    private var cached: String? = null

    /**
     * @return the MMKV crypt key, or null when the Keystore is unusable on this device. Callers then
     *         fall back to an unencrypted store so the app still works; the failure is logged.
     */
    @Synchronized
    fun getKey(context: Context): String? {
        cached?.let { return it }
        return try {
            val dir = context.noBackupFilesDir
            RandomAccessFile(File(dir, LOCK_FILE), "rw").use { lockFile ->
                lockFile.channel.lock().use {
                    val file = File(dir, KEY_FILE)
                    val key = readKey(file) ?: createKey(file)
                    cached = key
                    key
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Storage key unavailable, config storage is NOT encrypted on this device", e)
            null
        }
    }

    private fun wrapKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(WRAP_KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    /** Decrypts the stored key, or returns null when there is none or it can no longer be decrypted. */
    private fun readKey(file: File): String? {
        if (!file.exists()) return null
        return try {
            val blob = file.readBytes()
            if (blob.size <= GCM_IV_BYTES) return null
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                wrapKey(),
                GCMParameterSpec(GCM_TAG_BITS, blob, 0, GCM_IV_BYTES)
            )
            String(cipher.doFinal(blob, GCM_IV_BYTES, blob.size - GCM_IV_BYTES), Charsets.UTF_8)
                .takeIf { it.length == KEY_LENGTH }
        } catch (e: Exception) {
            // Keystore entry lost (e.g. lock-screen reset on some devices): the old data is unreadable.
            Log.e(TAG, "Stored storage key could not be decrypted, creating a new one", e)
            null
        }
    }

    private fun createKey(file: File): String {
        val random = SecureRandom()
        val key = buildString(KEY_LENGTH) {
            repeat(KEY_LENGTH) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey())
        val blob = cipher.iv + cipher.doFinal(key.toByteArray(Charsets.UTF_8))

        // write to a temp file first so a crash never leaves a half-written key behind
        val tmp = File(file.parentFile, "$KEY_FILE.tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) {
            file.writeBytes(blob)
            tmp.delete()
        }
        return key
    }
}
