//
//  KeyTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class KeyTest {

    @Test
    void getHeaderTest1() {
        Key key = new Key();
        assertEquals("KEY", key.getHeader());
        assertEquals("KEY", Key.HEADER);

        try {
            Key k = Key.generateKey(KeyCapability.EXCHANGE);

            k.addItemLink(Commons.getIntermediateKey());
            k.addItemLink(Commons.getAudienceKey());

            String s = k.exportToEncoded();
            int i = 0;
        } catch (Exception e) {

        }

    }

    @Test
    void claimTest1() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertNull(key.getClaim(Claim.ISS));
        key.putClaim(Claim.ISS, Commons.getAudienceIdentity().getClaim(Claim.SUB));
        assertEquals((UUID) Commons.getAudienceIdentity().getClaim(Claim.SUB), key.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertNotNull(key.getClaim(Claim.IAT));
        key.removeClaim(Claim.IAT);
        assertNull(key.getClaim(Claim.IAT));
    }

    @Test
    void claimTest3() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(key.getClaim(Claim.AMB));
            key.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.AUD));
            key.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(key.getClaim(Claim.CTX));
            key.putClaim(Claim.EXP, Instant.now());
            assertNotNull(key.getClaim(Claim.EXP));
            key.putClaim(Claim.IAT, Instant.now());
            assertNotNull(key.getClaim(Claim.IAT));
            key.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.ISS));
            key.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.KID));
            key.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(key.getClaim(Claim.MTD));
            key.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.SUB));
            key.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(key.getClaim(Claim.SYS));
            key.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(key.getClaim(Claim.UID));
            try { key.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.KEY, key.getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); key.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { key.putClaim(Claim.PUB, key.getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            key.sign(Commons.getIssuerKey());
            try { key.removeClaim(Claim.IAT); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { key.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), Commons.CONTEXT);
            key.sign(Commons.getIssuerKey());
            key.strip();
            key.removeClaim(Claim.CTX);
            key.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void keyTest1() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.SIGN));
        assertNotNull(key.getClaim(Claim.UID));
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(KeyCapability.EXCHANGE);
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.EXCHANGE));
        assertNotNull(key.getClaim(Claim.UID));
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyCapabilityTest1() {
        Key signKey = Key.generateKey(KeyCapability.SIGN);
        assertEquals(Dime.crypto.getDefaultSuiteName(), signKey.getCryptoSuiteName());
        assertNotNull(signKey.getSecret());
        assertNotNull(signKey.getPublic());
        List<KeyCapability> caps = signKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.SIGN));
        assertEquals(1, caps.size());
        assertTrue(signKey.hasCapability(KeyCapability.SIGN));
        assertFalse(signKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(signKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest2() {
        Key exchangeKey = Key.generateKey(KeyCapability.EXCHANGE);
        assertEquals(Dime.crypto.getDefaultSuiteName(), exchangeKey.getCryptoSuiteName());
        assertNotNull(exchangeKey.getSecret());
        assertNotNull(exchangeKey.getPublic());
        List<KeyCapability> caps = exchangeKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.EXCHANGE));
        assertEquals(1, caps.size());
        assertFalse(exchangeKey.hasCapability(KeyCapability.SIGN));
        assertTrue(exchangeKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(exchangeKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest3() {
        Key encryptionKey = Key.generateKey(KeyCapability.ENCRYPT);
        assertEquals(Dime.crypto.getDefaultSuiteName(), encryptionKey.getCryptoSuiteName());
        assertNotNull(encryptionKey.getSecret());
        assertNull(encryptionKey.getPublic());
        List<KeyCapability> caps = encryptionKey.getCapability();
        assertNotNull(caps);
        assertTrue(caps.contains(KeyCapability.ENCRYPT));
        assertEquals(1, caps.size());
        assertFalse(encryptionKey.hasCapability(KeyCapability.SIGN));
        assertFalse(encryptionKey.hasCapability(KeyCapability.EXCHANGE));
        assertTrue(encryptionKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyCapabilityTest4() {
        List<KeyCapability> caps = List.of(KeyCapability.SIGN, KeyCapability.EXCHANGE);
        try {
            Key.generateKey(caps, Dime.NO_EXPIRATION, null, null, Dime.crypto.getDefaultSuiteName());
            fail("Expected exception never thrown.");
        } catch (IllegalArgumentException ignored) { /* All is well good */ }
        catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void keyCapabilityTest5() {
        try {
            Key key1 = Key.generateKey(KeyCapability.SIGN);
            String exported1 = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported1);
            assertNotNull(key2);
            assertTrue(key2.hasCapability(KeyCapability.SIGN));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void exportTest1() {
        Key key = Key.generateKey(List.of(KeyCapability.SIGN));
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Commons.fullHeaderFor(Key.HEADER)));
        assertEquals(2, exported.split("\\.").length);
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTAzVDE3OjM3OjAyLjYzMDAzOFoiLCJrZXkiOiJTVE4uYUJqa3pLWDJCNVp3RzFucmJtTkZtdWdacDZvM2k2Rms4b1ZtanRmb3B2Z1RQSmNQY0VNb3R0WmppMmVqVW1NV2dFRHVrTER5RkJjaFR3NUtCb0tqRkY1NXdDVFdrIiwicHViIjoiU1ROLkxvOGNRYlVVOXdpRFkxcmdEYnhZREF6c204Z2lzN1JyREZzbkgzQmN2Ylk4d3BCTkMiLCJ1aWQiOiJjOGYyNmIxZi0zNDA2LTRjMjktYTQ3ZS1iODQ4Mjc4MGFiNjQifQ";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(1, key.getCapability().size());
            assertTrue(key.hasCapability(KeyCapability.SIGN));
            assertEquals(UUID.fromString("c8f26b1f-3406-4c29-a47e-b8482780ab64"), key.getClaim(Claim.UID));
            assertEquals(Instant.parse("2022-10-03T17:37:02.630038Z"), key.getClaim(Claim.IAT));
            assertEquals("STN.aBjkzKX2B5ZwG1nrbmNFmugZp6o3i6Fk8oVmjtfopvgTPJcPcEMottZji2ejUmMWgEDukLDyFBchTw5KBoKjFF55wCTWk", key.getSecret());
            assertEquals("STN.Lo8cQbUU9wiDY1rgDbxYDAzsm8gis7RrDFsnH3BcvbY8wpBNC", key.getPublic());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN), 120, UUID.randomUUID(), Commons.CONTEXT);
            assertNotNull(key.getSecret());
            Key pubOnly = key.publicCopy();
            assertNull(pubOnly.getSecret());
            assertEquals(key.getPublic(), pubOnly.getPublic());
            assertEquals((UUID) key.getClaim(Claim.UID), pubOnly.getClaim(Claim.UID));
            assertEquals((Instant)key.getClaim(Claim.IAT), pubOnly.getClaim(Claim.IAT));
            assertEquals((Instant) key.getClaim(Claim.EXP), pubOnly.getClaim(Claim.EXP));
            assertEquals((UUID) key.getClaim(Claim.ISS), pubOnly.getClaim(Claim.ISS));
            assertEquals((String) key.getClaim(Claim.CTX), pubOnly.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest2() {
        try {
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            Key pubOnly = Commons.getIssuerKey().publicCopy();
            message.verify(pubOnly);
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Key key = Key.generateKey(List.of(KeyCapability.SIGN), context);
        assertEquals(context, key.getClaim(Claim.CTX));
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN), context);
            String exported = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported);
            assertNotNull(key2);
            assertEquals(context, key2.getClaim(Claim.CTX));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try { Key.generateKey(List.of(KeyCapability.SIGN), context); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
    }

    @Test
    void stripTest1() {
        try {
            Key key = Key.generateKey(KeyCapability.ENCRYPT);
            key.sign(Commons.getIssuerKey());
            key.sign(Commons.getAudienceKey());
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerKey()));
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getAudienceKey()));
            assertTrue(key.strip(Commons.getAudienceKey()));
            assertEquals(IntegrityState.COMPLETE, key.verify(Commons.getIssuerKey()));
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, key.verify(Commons.getAudienceKey()));
            assertFalse(key.strip(Commons.getAudienceKey()));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}