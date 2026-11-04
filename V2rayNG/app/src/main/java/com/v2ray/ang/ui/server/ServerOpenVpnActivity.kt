package com.v2ray.ang.ui.server

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import com.v2ray.ang.R
import com.v2ray.ang.dto.entities.ProfileItem
import com.v2ray.ang.enums.EConfigType
import com.v2ray.ang.extension.toast
import com.v2ray.ang.fmt.OpenVpnFmt
import com.v2ray.ang.ui.compose.FormTextField

/** Editor for OpenVPN profiles: the `.ovpn` text plus the optional user name and password. */
class ServerOpenVpnActivity : BaseServerActivity() {

    override val serverConfigType: EConfigType = EConfigType.OPENVPN

    private var ovpnText: String = ""

    @Composable
    override fun ScreenContent() {
        val uiState = rememberSaveable(saver = ServerUiState.Saver) {
            ServerUiState.from(initialConfig = initialConfig)
        }.apply {
            configType = serverConfigType
        }
        var text by rememberSaveable { mutableStateOf(initialConfig.ovpnConfig.orEmpty()) }
        ovpnText = text

        ServerEditorScaffold(
            title = serverConfigType.toString(),
            onSaveClick = {
                val remote = OpenVpnFmt.readRemote(text)
                if (remote == null) {
                    toast(R.string.toast_openvpn_config_invalid)
                } else {
                    // address and port come from the `remote` line of the file
                    uiState.address = remote.first
                    uiState.port = remote.second
                    saveServer(uiState)
                }
            }
        ) {
            FormTextField(
                stringResource(R.string.server_lab_remarks),
                uiState.remarks,
                { uiState.remarks = it }
            )
            FormTextField(
                stringResource(R.string.server_lab_ovpn_config),
                text,
                { text = it },
                maxLines = 14,
                placeholder = "client\ndev tun\nremote example.com 1194\n<ca>…</ca>"
            )
            FormTextField(
                stringResource(R.string.server_lab_ssh_username),
                uiState.username,
                { uiState.username = it }
            )
            FormTextField(
                stringResource(R.string.server_lab_ssh_password),
                uiState.password,
                { uiState.password = it }
            )
        }
    }

    override fun validateProtocolConfig(config: ProfileItem): Boolean {
        val text = ovpnText
        val remote = OpenVpnFmt.readRemote(text)
        if (remote == null) {
            toast(R.string.toast_openvpn_config_invalid)
            return false
        }
        if (OpenVpnFmt.needsCredentials(text) && (config.username.isNullOrBlank() || config.password.isNullOrBlank())) {
            toast(R.string.toast_ssh_credentials_required)
            return false
        }
        config.ovpnConfig = text.trim() + "\n"
        config.mode = remote.third
        return true
    }
}
