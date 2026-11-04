package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.ui.compose.FormTextField

/** Editor for Cisco AnyConnect profiles: server, port (typed in by the user), user name, password and an optional group. */
class ServerCiscoActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.ANYCONNECT

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply {
            configType = serverConfigType
        }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            FormTextField(
                stringResource(R.string.server_lab_ssh_username),
                uiState.username,
                { uiState.username = it }
            )
            FormTextField(
                stringResource(R.string.server_lab_ssh_password),
                uiState.password,
                { uiState.password = it },
                isError = uiState.isPasswordError
            )
            FormTextField(
                stringResource(R.string.server_lab_cisco_group),
                uiState.path,
                { uiState.path = it }
            )
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        if (config.username.isNullOrBlank() || config.password.isNullOrBlank()) {
            toast(R.string.toast_ssh_credentials_required)
            return false
        }
        return true
    }
}
