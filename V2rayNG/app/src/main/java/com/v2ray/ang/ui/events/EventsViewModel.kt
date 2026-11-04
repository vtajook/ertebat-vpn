package com.v2ray.ang.ui.events

import android.app.Application
import androidx.lifecycle.viewModelScope
import com.v2ray.ang.handler.EventLog
import com.v2ray.ang.ui.base.BaseViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class EventFilter { All, Success, Error, Info }

data class EventsUiState(
    val entries: List<EventLog.Entry> = emptyList(),
    val filter: EventFilter = EventFilter.All,
)

/** Which filter an entry belongs to. */
internal fun filterOf(kind: String): EventFilter = when (kind) {
    EventLog.KIND_CONNECTED -> EventFilter.Success
    EventLog.KIND_FAILED -> EventFilter.Error
    else -> EventFilter.Info
}

internal fun applyFilter(entries: List<EventLog.Entry>, filter: EventFilter): List<EventLog.Entry> =
    if (filter == EventFilter.All) entries else entries.filter { filterOf(it.kind) == filter }

class EventsViewModel(application: Application) : BaseViewModel(application) {
    private val _state = MutableStateFlow(EventsUiState())
    val state: StateFlow<EventsUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun load() {
        viewModelScope.launch(Dispatchers.IO) {
            val all = EventLog.all()
            _state.update { it.copy(entries = all) }
        }
    }

    fun setFilter(filter: EventFilter) {
        _state.update { it.copy(filter = filter) }
    }

    fun clear() {
        viewModelScope.launch(Dispatchers.IO) {
            EventLog.clear()
            _state.update { it.copy(entries = emptyList()) }
        }
    }
}
