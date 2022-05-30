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
import io.dimeformat.enums.KeyType;
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
        Key key = Key.generateKey(KeyType.IDENTITY);
        assertSame(key.getKeyType(), KeyType.IDENTITY);
        assertNotNull(key.getUniqueId());
        assertNotNull(key.getPublic());
        assertNotNull(key.getSecret());
    }

    @Test
    void keyTest2() {
        Key key = Key.generateKey(KeyType.EXCHANGE);
        assertSame(key.getKeyType(), KeyType.EXCHANGE);
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
            assertTrue(key2.hasUsage(KeyUsage.SIGN));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void exportTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Envelope.HEADER + ":" + Key.ITEM_IDENTIFIER));
        assertEquals(2, exported.split("\\.").length);
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
            Key key = Item.importFromEncoded(exported);
            assertNotNull(key);
            assertEquals(KeyType.IDENTITY, key.getKeyType());
            assertEquals(UUID.fromString("3f00cd13-4474-4c04-9b6b-7383d490f17f"), key.getUniqueId());
            assertEquals(Instant.parse("2021-11-18T08:48:25.137918Z"), key.getIssuedAt());
            assertEquals("S21Tkgozxhzk5ttFgHhgey6t1419WCMUUM98ZhniVAjfT4iniUknfUrNqfPqdLua2SvxFf8SXkHS1PTBCrdkYXN6qTEm7Mwa2LRd", key.getSecret());
            assertEquals("S21TZSL1uvF5mTWKiomQKNhmkcYPw5XZ1VBfbSPqmyqG5GaNCUGB7Pj19WShuJuLkhREEJ4kLThehqRkadJLSTAkL9DtyhmLxGfn", key.getPublic());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void publicOnlyTest1() {
        try {
            Key key = Key.generateKey(KeyType.IDENTITY, 120, UUID.randomUUID(), "Racecar is racecar backwards.");
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
        Key key = Key.generateKey(KeyType.IDENTITY, context);
        assertEquals(context, key.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.generateKey(KeyType.IDENTITY, context);
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
            Key.generateKey(KeyType.IDENTITY, context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}