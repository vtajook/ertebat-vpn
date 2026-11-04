package com.v2ray.ang.handler

import com.tencent.mmkv.MMKV
import org.json.JSONArray
import org.json.JSONObject

/**
 * Small persistent history of connection events (connected, disconnected, failed) for the logs screen.
 * Only the server name and a short error text are kept, never credentials or configs.
 */
object EventLog {
    const val KIND_CONNECTED = "connected"
    const val KIND_DISCONNECTED = "disconnected"
    const val KIND_FAILED = "failed"

    private const val STORE_ID = "egn_events"
    private const val KEY = "list"
    private const val MAX = 100

    data class Entry(val kind: String, val detail: String, val timeMs: Long)

    private val store: MMKV by lazy { MMKV.mmkvWithID(STORE_ID, MMKV.MULTI_PROCESS_MODE) }

    @Synchronized
    fun record(kind: String, detail: String?) {
        try {
            val list = all().toMutableList()
            list.add(0, Entry(kind, detail.orEmpty().take(300), System.currentTimeMillis()))
            while (list.size > MAX) list.removeAt(list.size - 1)
            store.encode(KEY, toJson(list))
        } catch (_: Throwable) {
            // history is best effort
        }
    }

    /** Newest first. */
    @Synchronized
    fun all(): List<Entry> {
        val text = store.decodeString(KEY) ?: return emptyList()
        return try {
            val arr = JSONArray(text)
            (0 until arr.length()).map {
                val o = arr.getJSONObject(it)
                Entry(o.optString("k"), o.optString("d"), o.optLong("t"))
            }
        } catch (_: Throwable) {
            emptyList()
        }
    }

    @Synchronized
    fun clear() {
        store.removeValueForKey(KEY)
    }

    private fun toJson(list: List<Entry>): String {
        val arr = JSONArray()
        list.forEach { arr.put(JSONObject().put("k", it.kind).put("d", it.detail).put("t", it.timeMs)) }
        return arr.toString()
    }
}
