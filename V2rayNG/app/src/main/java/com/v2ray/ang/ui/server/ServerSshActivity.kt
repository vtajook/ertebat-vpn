package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.fmt.SshFmt
import com.v2ray.ang.ui.compose.FormTextField
import com.v2ray.ang.ui.compose.SettingsSwitchItem

/** Editor for `ssh://user:pass@host:port#name` profiles (tunnelled through a local SOCKS5 proxy). */
class ServerSshActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.SSH

    @Composable
    override fun ScreenContent() {
        @Suppress("UNUSED_VARIABLE")
        val scope = rememberCoroutineScope()
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(
                initialConfig = initialConfig
            ).also {
                // a brand new SSH profile starts on the standard SSH port
                if (initialConfig.serverPort.isNullOrBlank()) it.port = SshFmt.DEFAULT_SSH_PORT.toString()
                // UDP (WhatsApp calls) is always on; 7300 unless the config says otherwise
                if (it.udpgwPort.isBlank()) it.udpgwPort = "7300"
            }
        }.apply {
            configType = serverConfigType
        }

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = { saveServer(uiState) }
        ) {
            CommonBasicFields(uiState)
            SshProtocolFields(uiState)
        }
    }

    @Composable
    private fun SshProtocolFields(state: ServerUiState) {
        FormTextField(
            stringResource(R.string.server_lab_ssh_username),
            state.username,
            { state.username = it }
        )
        FormTextField(
            stringResource(R.string.server_lab_ssh_password),
            state.password,
            { state.password = it },
            isError = state.isPasswordError
        )
        SettingsSwitchItem(
            title = stringResource(R.string.server_lab_ssh_tls),
            checked = state.streamSecurity.equals("tls", true),
            onCheckedChange = {
                state.streamSecurity = if (it) "tls" else ""
                if (it && state.sni.isBlank()) state.allowInsecure = true
            }
        )
        if (state.streamSecurity.equals("tls", true)) {
            FormTextField(
                stringResource(R.string.server_lab_ssh_sni),
                state.sni,
                { state.sni = it }
            )
            SettingsSwitchItem(
                title = stringResource(R.string.server_lab_ssh_allow_insecure),
                checked = state.allowInsecure,
                onCheckedChange = { state.allowInsecure = it }
            )
        }
        FormTextField(
            stringResource(R.string.server_lab_ssh_udpgw),
            state.udpgwPort,
            { state.udpgwPort = it.filter { c -> c.isDigit() }.take(5) }
        )
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        if (config.username.isNullOrBlank() || config.password.isNullOrBlank()) {
            toast(R.string.toast_ssh_credentials_required)
            return false
        }
        return true
    }
}
