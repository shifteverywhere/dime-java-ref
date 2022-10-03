//
//  CryptoTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.List;
import io.dimeformat.enums.KeyCapability;
import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {

    @Test
    void generateKeyNameTest1() {
        Key key = Key.generateKey(List.of(KeyCapability.SIGN));
        String identifier = Dime.crypto.generateKeyName(key);
        assertNotNull(identifier);
        assertEquals(16, identifier.length());
    }

    @Test
    void generateKeyNameTest2() {
        try {
            String hex = "506f85299f6a2a4b";
            String encoded = "Di:KEY.eyJ1aWQiOiIyYTY5ZjJkMC1kNzQ2LTQxNzYtOTg5NS01MDcyNzRlNzJiYjkiLCJwdWIiOiJTVE4uMkI4VzZCNjRRTTlBeDRvdzNjb1Y0TlJrTW95MWNXUzR4N0FYYTRzdnd5dVJlQWtQNG8iLCJpYXQiOiIyMDIyLTA2LTExVDEwOjI3OjM0Ljk5NjIzOFoiLCJ1c2UiOlsic2lnbiJdLCJrZXkiOiJTVE4uQXhwZ3Z2N0FYS2lhalNEQlBCZ0ZCbndzSkoyUXpXSGFUaWpFY29LcEx6YUo5VVlpOGVKNGg0bkJFQnVSN2NldWtVQm5waWU1NkxZQW5EdHQ3Y2V3aVczd0FGTDdFIn0";
            Key key = Item.importFromEncoded(encoded);
            String identifier = Dime.crypto.generateKeyName(key);
            assertEquals(hex, identifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest1() {
        try {
            String data = Commons.PAYLOAD;
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            byte[] sig = Dime.crypto.generateSignature(data, key);
            Dime.crypto.verifySignature(data, sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest2() {
        try {
            byte[] sig = Utility.fromBase64("Fdb/SMaBcpWKzpGCTuqsYduh6OnJ6UXyDAUPHTbNZCioFd1Ek5VcGys8Zg3TGzur3GusB9lbWPyDp2L+pO0LAQ");
            String encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTAzVDE3OjI5OjQ1Ljc2NzEzMFoiLCJrZXkiOiJTVE4uNTRWNTd5RHRnMWpZN2J0SlhmaG9aeU1TeE5ndGtIb3lqcFZ3ZEU1UnRVZzl2c1prRHlzNzdqWWoxQmpTQVJIN1lHQkRuNDJSM3hhekh0dVZUNDU5MzRTN3o3cjdFIiwicHViIjoiU1ROLjJyZWZjM0Z4RmJYUkwzeDY4Q0VYdzhSWU1LTmd1OVpuajNMR3hDbkFYMjl0anRUVVZDIiwidWlkIjoiZmQwZDhlMzYtOTc0ZS00MTIwLWI2NWUtMDAxYzdkNDM3N2ExIn0";
            Key key = Item.importFromEncoded(encoded);
            Dime.crypto.verifySignature(Commons.PAYLOAD, sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSharedSecretTest1() {
        try {
            Key clientKey = Key.generateKey(List.of(KeyCapability.EXCHANGE));
            Key serverKey = Key.generateKey(List.of(KeyCapability.EXCHANGE));
            Key shared1 = clientKey.generateSharedSecret(serverKey.publicCopy(), List.of(KeyCapability.ENCRYPT));
            Key shared2 = clientKey.publicCopy().generateSharedSecret(serverKey, List.of(KeyCapability.ENCRYPT));
            assertTrue(shared1.hasCapability(KeyCapability.ENCRYPT));
            assertTrue(shared2.hasCapability(KeyCapability.ENCRYPT));
            assertEquals(shared1.getSecret(), shared2.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSharedSecretTest2() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjQ2ODE0OFoiLCJrZXkiOiIyREJWdDhWOWhSOTU0Mjl5MWdja3lXaVBoOXhVRVBxb2hFUTFKQjRnSjlodmpaV1hheE0zeWVURXYiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMyWiIsInB1YiI6IjJEQlZ0bk1aUDc5aEpWTUpwVnlIR29rRU1QWEM2cXkzOHNoeVRIaEpBekY5TlVRdlFmUWRxNGRjMyJ9";
            String encodedShared = "STN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
            Key clientKey = Item.importFromEncoded(encodedClient);
            assertNotNull(clientKey);
            Key serverKey = Item.importFromEncoded(encodedServer);
            assertNotNull(serverKey);
            Key shared = clientKey.generateSharedSecret(serverKey, List.of(KeyCapability.ENCRYPT));
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSharedSecretTest3() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDE1MloiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMxNloiLCJrZXkiOiIyREJWdDhWOWJ4R2pGS0xoa2FodEo0UUtRc3F6Y1ZjNGFqeWNxSnQ4eFZQTlZkYnBveHBLdkFZaUoiLCJwdWIiOiIyREJWdG5NWlA3OWhKVk1KcFZ5SEdva0VNUFhDNnF5MzhzaHlUSGhKQXpGOU5VUXZRZlFkcTRkYzMifQ";
            String encodedShared = "STN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
            Key clientKey = Item.importFromEncoded(encodedClient);
            assertNotNull(clientKey);
            Key serverKey = Item.importFromEncoded(encodedServer);
            assertNotNull(serverKey);
            Key shared = clientKey.generateSharedSecret(serverKey, List.of(KeyCapability.ENCRYPT));
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void encryptTest1() {
        try {
            String data = Commons.PAYLOAD;
            Key key = Key.generateKey(List.of(KeyCapability.ENCRYPT));
            byte[] cipherText = Dime.crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Dime.crypto.decrypt(cipherText, key);
            assertNotNull(plainText);
            assertEquals(data, new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void encryptTest2() {
        try {
            String data = Commons.PAYLOAD;
            String encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            Key key = Item.importFromEncoded(encoded);
            byte[] cipherText = Dime.crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Dime.crypto.decrypt(cipherText, key);
            assertNotNull(plainText);
            assertEquals(data, new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void decryptTest1() {
        try {
            String cipherText = "NHubU8GAScHW7Re7+Ne8UPBB9xVEJX3WGUO4dMNNtR0VB9T5gJ8OZIpfgpURRkhuJD/7g+flZofsaP8NTVkhGrUFcZ4b";
            String encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            Key key = Item.importFromEncoded(encoded);
             byte[] plainText = Dime.crypto.decrypt(Utility.fromBase64(cipherText), key);
            assertNotNull(plainText);
            assertEquals(Commons.PAYLOAD, new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateHashTest1() {
        try {
            String ref = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            byte[] data = Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8);
            byte[] hash = Dime.crypto.generateHash(data);
            assertNotNull(hash);
            String hex = Utility.toHex(hash);
            assertEquals(ref, hex);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void cryptoPlatformExchangeTest1() {
        try {
            Key clientKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
            Key serverKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");
            assertNotNull(clientKey);
            assertNotNull(serverKey);
            byte[] shared1 = Dime.crypto.generateSharedSecret(clientKey, serverKey.publicCopy(), List.of(KeyCapability.ENCRYPT));
            byte[] shared2 = Dime.crypto.generateSharedSecret(clientKey.publicCopy(), serverKey, List.of(KeyCapability.ENCRYPT));
            String hash1 = Utility.toHex(shared1);
            String hash2 = Utility.toHex(shared2);
            assertEquals("8c0c2c98d5839bc59a61fa0bea987aea6f058c08c214ab65d1a87e2a7913cea9", hash1);
            assertEquals(hash1, hash2);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
