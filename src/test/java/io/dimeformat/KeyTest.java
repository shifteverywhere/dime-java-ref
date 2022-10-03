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

import io.dimeformat.enums.KeyCapability;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class KeyTest {

    @Test
    void getItemIdentifierTest1() {
        Key key = new Key();
        assertEquals("KEY", key.getItemIdentifier());
        assertEquals("KEY", Key.ITEM_IDENTIFIER);
    }

    @Test
    void keyTest1() {
        Key key = Key.generateKey(List.of(KeyCapability.SIGN));
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.SIGN));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(List.of(KeyCapability.EXCHANGE));
        assertEquals(1, key.getCapability().size());
        assertTrue(key.hasCapability(KeyCapability.EXCHANGE));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyUsageTest1() {
        Key signKey = Key.generateKey(List.of(KeyCapability.SIGN));
        assertEquals(Dime.crypto.getDefaultSuiteName(), signKey.getCryptoSuiteName());
        assertNotNull(signKey.getSecret());
        assertNotNull(signKey.getPublic());
        List<KeyCapability> usage = signKey.getCapability();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyCapability.SIGN));
        assertEquals(1, usage.size());
        assertTrue(signKey.hasCapability(KeyCapability.SIGN));
        assertFalse(signKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(signKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyUsageTest2() {
        Key exchangeKey = Key.generateKey(List.of(KeyCapability.EXCHANGE));
        assertEquals(Dime.crypto.getDefaultSuiteName(), exchangeKey.getCryptoSuiteName());
        assertNotNull(exchangeKey.getSecret());
        assertNotNull(exchangeKey.getPublic());
        List<KeyCapability> usage = exchangeKey.getCapability();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyCapability.EXCHANGE));
        assertEquals(1, usage.size());
        assertFalse(exchangeKey.hasCapability(KeyCapability.SIGN));
        assertTrue(exchangeKey.hasCapability(KeyCapability.EXCHANGE));
        assertFalse(exchangeKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyUsageTest3() {
        Key encryptionKey = Key.generateKey(List.of(KeyCapability.ENCRYPT));
        assertEquals(Dime.crypto.getDefaultSuiteName(), encryptionKey.getCryptoSuiteName());
        assertNotNull(encryptionKey.getSecret());
        assertNull(encryptionKey.getPublic());
        List<KeyCapability> usage = encryptionKey.getCapability();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyCapability.ENCRYPT));
        assertEquals(1, usage.size());
        assertFalse(encryptionKey.hasCapability(KeyCapability.SIGN));
        assertFalse(encryptionKey.hasCapability(KeyCapability.EXCHANGE));
        assertTrue(encryptionKey.hasCapability(KeyCapability.ENCRYPT));
    }

    @Test
    void keyUsageTest4() {
        List<KeyCapability> use = List.of(KeyCapability.SIGN, KeyCapability.EXCHANGE);
        try {
            Key.generateKey(use, -1, null, null, Dime.crypto.getDefaultSuiteName());
            fail("Expected exception never thrown.");
        } catch (IllegalArgumentException ignored) { /* All is well good */ }
        catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void keyUsageTest5() {
        try {
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN));
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
        assertTrue(exported.startsWith(Commons.fullHeaderFor(Key.ITEM_IDENTIFIER)));
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
            assertEquals(UUID.fromString("c8f26b1f-3406-4c29-a47e-b8482780ab64"), key.getUniqueId());
            assertEquals(Instant.parse("2022-10-03T17:37:02.630038Z"), key.getIssuedAt());
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
            assertEquals(key.getUniqueId(), pubOnly.getUniqueId());
            assertEquals(key.getIssuedAt(), pubOnly.getIssuedAt());
            assertEquals(key.getExpiresAt(), pubOnly.getExpiresAt());
            assertEquals(key.getIssuerId(), pubOnly.getIssuerId());
            assertEquals(key.getContext(), pubOnly.getContext());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest2() {
        try {
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), Dime.VALID_FOR_1_MINUTE);
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
        assertEquals(context, key.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(List.of(KeyCapability.SIGN), context);
            String exported = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported);
            assertNotNull(key2);
            assertEquals(context, key2.getContext());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Key.generateKey(List.of(KeyCapability.SIGN), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}