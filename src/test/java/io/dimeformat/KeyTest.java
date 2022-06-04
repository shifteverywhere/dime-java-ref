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

import io.dimeformat.enums.KeyUsage;
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
        Key key = Key.generateKey(List.of(KeyUsage.SIGN));
        assertEquals(1, key.getKeyUsage().size());
        assertTrue(key.hasUsage(KeyUsage.SIGN));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(List.of(KeyUsage.EXCHANGE));
        assertEquals(1, key.getKeyUsage().size());
        assertTrue(key.hasUsage(KeyUsage.EXCHANGE));
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyUsageTest1() {
        Key signKey = Key.generateKey(List.of(KeyUsage.SIGN));
        assertEquals(Dime.crypto.getDefaultSuiteName(), signKey.getCryptoSuiteName());
        assertNotNull(signKey.getSecret());
        assertNotNull(signKey.getPublic());
        List<KeyUsage> usage = signKey.getKeyUsage();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyUsage.SIGN));
        assertEquals(1, usage.size());
        assertTrue(signKey.hasUsage(KeyUsage.SIGN));
        assertFalse(signKey.hasUsage(KeyUsage.EXCHANGE));
        assertFalse(signKey.hasUsage(KeyUsage.ENCRYPT));
    }

    @Test
    void keyUsageTest2() {
        Key exchangeKey = Key.generateKey(List.of(KeyUsage.EXCHANGE));
        assertEquals(Dime.crypto.getDefaultSuiteName(), exchangeKey.getCryptoSuiteName());
        assertNotNull(exchangeKey.getSecret());
        assertNotNull(exchangeKey.getPublic());
        List<KeyUsage> usage = exchangeKey.getKeyUsage();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyUsage.EXCHANGE));
        assertEquals(1, usage.size());
        assertFalse(exchangeKey.hasUsage(KeyUsage.SIGN));
        assertTrue(exchangeKey.hasUsage(KeyUsage.EXCHANGE));
        assertFalse(exchangeKey.hasUsage(KeyUsage.ENCRYPT));
    }

    @Test
    void keyUsageTest3() {
        Key encryptionKey = Key.generateKey(List.of(KeyUsage.ENCRYPT));
        assertEquals(Dime.crypto.getDefaultSuiteName(), encryptionKey.getCryptoSuiteName());
        assertNotNull(encryptionKey.getSecret());
        assertNull(encryptionKey.getPublic());
        List<KeyUsage> usage = encryptionKey.getKeyUsage();
        assertNotNull(usage);
        assertTrue(usage.contains(KeyUsage.ENCRYPT));
        assertEquals(1, usage.size());
        assertFalse(encryptionKey.hasUsage(KeyUsage.SIGN));
        assertFalse(encryptionKey.hasUsage(KeyUsage.EXCHANGE));
        assertTrue(encryptionKey.hasUsage(KeyUsage.ENCRYPT));
    }

    @Test
    void keyUsageTest4() {
        List<KeyUsage> usage = List.of(KeyUsage.SIGN, KeyUsage.EXCHANGE);
        try {
            Key.generateKey(usage, -1, null, null, Dime.STANDARD_SUITE);
            fail("Expected exception never thrown.");
        } catch (IllegalArgumentException ignored) { /* All is well good */ }
        catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void keyUsageTest5() {
        try {
            Key key1 = Key.generateKey(List.of(KeyUsage.SIGN));
            String exported1 = key1.exportToEncoded();
            Key key2 = Item.importFromEncoded(exported1);
            assertNotNull(key2);
            assertTrue(key2.hasUsage(KeyUsage.SIGN));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void exportTest1() {
        Key key = Key.generateKey(List.of(KeyUsage.SIGN));
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Commons.fullHeaderFor(Key.ITEM_IDENTIFIER)));
        assertEquals(2, exported.split("\\.").length);
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di/1j:KEY.eyJ1aWQiOiJjMjhkOTY2OC1hNzU5LTQ4YjQtYmEzYi0zMTE0MWZmZjM0MTUiLCJwdWIiOiJEU1ROKzJkdGFnSm5ISlBxdFNkeEZrVnVCZWRaR2s2UHVIRkZKd1pEUVoyaWpzbWlyb0FDZmR0IiwiaWF0IjoiMjAyMi0wNS0zMFQxODoyNzozNS42NzI4OTJaIiwidXNlIjpbInNpZ24iXSwia2V5IjoiRFNUTis1MVdnNlVOakFxMnZodURERTRNdEoxNXVOTnBNbjVVRnR1OXVQTUphVlMzamhadnl5MThvcEpBU0haeUR0UE0yTmZvOTRROXhhaVlNdGZOSmZBcnNzVTc0S2Fkd2gifQ";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(1, key.getKeyUsage().size());
            assertTrue(key.hasUsage(KeyUsage.SIGN));
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
            Key key = Key.generateKey(List.of(KeyUsage.SIGN), 120, UUID.randomUUID(), "Racecar is racecar backwards.");
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
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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
        Key key = Key.generateKey(List.of(KeyUsage.SIGN), context);
        assertEquals(context, key.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(List.of(KeyUsage.SIGN), context);
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
            Key.generateKey(List.of(KeyUsage.SIGN), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}