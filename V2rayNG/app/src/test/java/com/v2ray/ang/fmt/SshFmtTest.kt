package com.v2ray.ang.fmt

import com.v2ray.ang.enums.EConfigType
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class SshFmtTest {

    @Test
    fun parsesStandardLink() {
        val profile = SshFmt.parse("ssh://user1:123456@example.com:2222#My%20Server")

        assertNotNull(profile)
        assertEquals(EConfigType.SSH, profile!!.configType)
        assertEquals("example.com", profile.server)
        assertEquals("2222", profile.serverPort)
        assertEquals("user1", profile.username)
        assertEquals("123456", profile.password)
        assertEquals("My Server", profile.remarks)
    }

    @Test
    fun missingPortUses22() {
        val profile = SshFmt.parse("ssh://user:pass@1.2.3.4#x")

        assertEquals("1.2.3.4", profile!!.server)
        assertEquals("22", profile.serverPort)
    }

    @Test
    fun missingRemarksFallsBackToUserAtHost() {
        val profile = SshFmt.parse("ssh://user:pass@example.com:22")

        assertEquals("user@example.com", profile!!.remarks)
    }

    @Test
    fun passwordMayContainAtSign() {
        val profile = SshFmt.parse("ssh://user:p@ss@example.com:22#n")

        assertEquals("user", profile!!.username)
        assertEquals("p@ss", profile.password)
        assertEquals("example.com", profile.server)
    }

    @Test
    fun percentEncodedPasswordIsDecoded() {
        val profile = SshFmt.parse("ssh://user:p%40ss%23%3A1@example.com:22#n")

        assertEquals("p@ss#:1", profile!!.password)
    }

    @Test
    fun parsesIpv6Host() {
        val profile = SshFmt.parse("ssh://user:pass@[2001:db8::1]:2200#v6")

        assertEquals("2001:db8::1", profile!!.server)
        assertEquals("2200", profile.serverPort)
    }

    @Test
    fun invalidLinksAreRejected() {
        assertNull(SshFmt.parse("ssh://example.com:22"))            // no credentials
        assertNull(SshFmt.parse("ssh://:pass@example.com:22"))       // empty user
        assertNull(SshFmt.parse("ssh://user:pass@:22"))              // empty host
        assertNull(SshFmt.parse("ssh://user:pass@example.com:abc"))  // bad port
        assertNull(SshFmt.parse("ssh://user:pass@example.com:70000")) // port out of range
        assertNull(SshFmt.parse("vmess://user:pass@example.com:22")) // wrong scheme
    }

    @Test
    fun toUriRoundTrips() {
        val original = SshFmt.parse("ssh://user:p%40ss@example.com:2222#Name")!!

        val link = EConfigType.SSH.protocolScheme + SshFmt.toUri(original)
        val parsed = SshFmt.parse(link)!!

        assertEquals(original.server, parsed.server)
        assertEquals(original.serverPort, parsed.serverPort)
        assertEquals(original.username, parsed.username)
        assertEquals(original.password, parsed.password)
        assertEquals(original.remarks, parsed.remarks)
    }
}
