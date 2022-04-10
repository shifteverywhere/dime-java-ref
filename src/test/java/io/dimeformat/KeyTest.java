//
//  KeyTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyType;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class KeyTest {

    @Test
    void getTagTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        assertEquals("KEY", key.getTag());
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
    void exportTest1() {
        Key key = Key.generateKey(KeyType.IDENTITY);
        String exported = key.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.startsWith(Envelope.HEADER + ":" + Key.TAG));
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
    void keyHeaderTest1() {
        byte[] aeadHeader = new byte[] { (byte)Dime.VERSION, (byte)0x10, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, AEAD, XChaCha20-Poly1305, 256-bit, extension, extension
        Key aead = Key.generateKey(KeyType.ENCRYPTION);
        assertNull(aead.getPublic());
        byte[] bytes = Base58.decode(aead.getSecret());
        assertNotNull(bytes);
        byte[] header = Utility.subArray(bytes, 0, 6);
        assertArrayEquals(aeadHeader, header);
    }

    @Test
    void keyHeaderTest2() {
        byte[] ecdhHeaderSecret = new byte[] { (byte)Dime.VERSION, (byte)0x40, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, public, extension, extension
        byte[] ecdhHeaderPublic = new byte[] { (byte)Dime.VERSION, (byte)0x40, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, private, extension, extension
        Key ecdh = Key.generateKey(KeyType.EXCHANGE);
        byte[] bytesSecret = Base58.decode(ecdh.getSecret());
        byte[] bytesPublic = Base58.decode(ecdh.getPublic());
        assertNotNull(bytesSecret);
        assertNotNull(bytesPublic);
        byte[] headerSecret = Utility.subArray(bytesSecret, 0, 6);
        byte[] headerPublic = Utility.subArray(bytesPublic, 0, 6);
        assertArrayEquals(ecdhHeaderSecret, headerSecret);
        assertArrayEquals(ecdhHeaderPublic, headerPublic);
    }

    @Test
    void keyHeaderTest3() {
        byte[] eddsaHeaderSecret = new byte[] { (byte)Dime.VERSION, (byte)0x80, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, public, extension, extension
        byte[] eddsaHeaderPublic = new byte[] { (byte)Dime.VERSION, (byte)0x80, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, private, extension, extension
        Key eddsa = Key.generateKey(KeyType.IDENTITY);
        byte[] bytesSecret = Base58.decode(eddsa.getSecret());
        byte[] bytesPublic = Base58.decode(eddsa.getPublic());
        assertNotNull(bytesSecret);
        assertNotNull(bytesPublic);
        byte[] headerSecret = Utility.subArray(bytesSecret, 0, 6);
        byte[] headerPublic = Utility.subArray(bytesPublic, 0, 6);
        assertArrayEquals(eddsaHeaderSecret, headerSecret);
        assertArrayEquals(eddsaHeaderPublic, headerPublic);
    }

    @Test
    void keyHeaderTest4() {
        byte[] hashHeader = new byte[] { (byte)Dime.VERSION, (byte)0xE0, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, Secure Hashing, Blake2b, 256-bit, extension, extension
        Key hash = Key.generateKey(KeyType.AUTHENTICATION);
        assertNull(hash.getPublic());
        byte[] bytes = Base58.decode(hash.getSecret());
        assertNotNull(bytes);
        byte[] header = Utility.subArray(bytes, 0, 6);
        assertArrayEquals(hashHeader, header);
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