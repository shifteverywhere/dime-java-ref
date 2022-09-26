//
//  KeyTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

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
        Key key = Key.generateKey(List.of(Key.Use.SIGN));
        assertEquals(1, key.getUse().size());
        assertTrue(key.hasUse(Key.Use.SIGN));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(List.of(Key.Use.EXCHANGE));
        assertEquals(1, key.getUse().size());
        assertTrue(key.hasUse(Key.Use.EXCHANGE));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyUsageTest1() {
        Key signKey = Key.generateKey(List.of(Key.Use.SIGN));
        assertEquals(Dime.crypto.getDefaultSuiteName(), signKey.getCryptoSuiteName());
        assertNotNull(signKey.getSecret());
        assertNotNull(signKey.getPublic());
        List<Key.Use> usage = signKey.getUse();
        assertNotNull(usage);
        assertTrue(usage.contains(Key.Use.SIGN));
        assertEquals(1, usage.size());
        assertTrue(signKey.hasUse(Key.Use.SIGN));
        assertFalse(signKey.hasUse(Key.Use.EXCHANGE));
        assertFalse(signKey.hasUse(Key.Use.ENCRYPT));
    }

    @Test
    void keyUsageTest2() {
        Key exchangeKey = Key.generateKey(List.of(Key.Use.EXCHANGE));
        assertEquals(Dime.crypto.getDefaultSuiteName(), exchangeKey.getCryptoSuiteName());
        assertNotNull(exchangeKey.getSecret());
        assertNotNull(exchangeKey.getPublic());
        List<Key.Use> usage = exchangeKey.getUse();
        assertNotNull(usage);
        assertTrue(usage.contains(Key.Use.EXCHANGE));
        assertEquals(1, usage.size());
        assertFalse(exchangeKey.hasUse(Key.Use.SIGN));
        assertTrue(exchangeKey.hasUse(Key.Use.EXCHANGE));
        assertFalse(exchangeKey.hasUse(Key.Use.ENCRYPT));
    }

    @Test
    void keyUsageTest3() {
        Key encryptionKey = Key.generateKey(List.of(Key.Use.ENCRYPT));
        assertEquals(Dime.crypto.getDefaultSuiteName(), encryptionKey.getCryptoSuiteName());
        assertNotNull(encryptionKey.getSecret());
        assertNull(encryptionKey.getPublic());
        List<Key.Use> usage = encryptionKey.getUse();
        assertNotNull(usage);
        assertTrue(usage.contains(Key.Use.ENCRYPT));
        assertEquals(1, usage.size());
        assertFalse(encryptionKey.hasUse(Key.Use.SIGN));
        assertFalse(encryptionKey.hasUse(Key.Use.EXCHANGE));
        assertTrue(encryptionKey.hasUse(Key.Use.ENCRYPT));
    }

    @Test
    void keyUsageTest4() {
        List<Key.Use> use = List.of(Key.Use.SIGN, Key.Use.EXCHANGE);
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
            Key key1 = Key.generateKey(List.of(Key.Use.SIGN));
            String exported1 = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported1);
            assertNotNull(key2);
            assertTrue(key2.hasUse(Key.Use.SIGN));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void exportTest1() {
        Key key = Key.generateKey(List.of(Key.Use.SIGN));
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Commons.fullHeaderFor(Key.ITEM_IDENTIFIER)));
        assertEquals(2, exported.split("\\.").length);
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:KEY.eyJ1aWQiOiJjMjhkOTY2OC1hNzU5LTQ4YjQtYmEzYi0zMTE0MWZmZjM0MTUiLCJwdWIiOiJEU1ROKzJkdGFnSm5ISlBxdFNkeEZrVnVCZWRaR2s2UHVIRkZKd1pEUVoyaWpzbWlyb0FDZmR0IiwiaWF0IjoiMjAyMi0wNS0zMFQxODoyNzozNS42NzI4OTJaIiwidXNlIjpbInNpZ24iXSwia2V5IjoiRFNUTis1MVdnNlVOakFxMnZodURERTRNdEoxNXVOTnBNbjVVRnR1OXVQTUphVlMzamhadnl5MThvcEpBU0haeUR0UE0yTmZvOTRROXhhaVlNdGZOSmZBcnNzVTc0S2Fkd2gifQ";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(1, key.getUse().size());
            assertTrue(key.hasUse(Key.Use.SIGN));
            assertEquals(UUID.fromString("c28d9668-a759-48b4-ba3b-31141fff3415"), key.getUniqueId());
            assertEquals(Instant.parse("2022-05-30T18:27:35.672892Z"), key.getIssuedAt());
            assertEquals("DSTN+51Wg6UNjAq2vhuDDE4MtJ15uNNpMn5UFtu9uPMJaVS3jhZvyy18opJASHZyDtPM2Nfo94Q9xaiYMtfNJfArssU74Kadwh", key.getSecret());
            assertEquals("DSTN+2dtagJnHJPqtSdxFkVuBedZGk6PuHFFJwZDQZ2ijsmiroACfdt", key.getPublic());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest1() {
        try {
            Key key = Key.generateKey(List.of(Key.Use.SIGN), 120, UUID.randomUUID(), Commons.CONTEXT);
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
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
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
        Key key = Key.generateKey(List.of(Key.Use.SIGN), context);
        assertEquals(context, key.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(List.of(Key.Use.SIGN), context);
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
            Key.generateKey(List.of(Key.Use.SIGN), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}