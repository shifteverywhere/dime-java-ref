//
//  CryptoTest.java
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
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {

    @Test
    void generateSignatureTest1() {
        try {
            String data = "Racecar is racecar backwards.";
            Key key = Key.generateKey(List.of(KeyUsage.SIGN));
            String sig = Dime.crypto.generateSignature(data, key);
            Dime.crypto.verifySignature(data, sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest2() {
        try {
            String sig = "3DYiduduCeMYt86jEBHJG981O1NxpYn3gBnkUxI3yG9penQxk+qR8G222asv5lLpbX7JOBS+CKouZGhR8NEdBg";
            String encoded = "Di/1j:KEY.eyJ1aWQiOiIzYWQ0Y2YyNi1lM2M1LTQ1YWYtYmRmNi02OGNmMDRjMTBhMWMiLCJwdWIiOiJEU1ROLjJKSGVwODZvOFl5UFU1b01MbmtpNUxZYkhHU0tOdEM3YXVrdmlOWEFyU0g5UnB0Ykt0IiwiaWF0IjoiMjAyMi0wNS0zMFQwNzoyNTowMC4wMDUxMjVaIiwidXNlIjpbInNpZ24iXSwia2V5IjoiRFNUTi5TMXJxejhLWkdGenpqWkRxUVVCZUdkYmVMdVZiQUVRYnFXUmVycGZEUW1CZjJHZkpCaWdWYkhDMVViTWRBallYVHRTdWM2ZHdrdHY5cDdLcXY0U2pDZldUd3VmSjkifQ";
            Key key = Item.importFromEncoded(encoded);
            Dime.crypto.verifySignature("Racecar is racecar backwards.", sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSharedSecretTest1() {
        try {
            Key clientKey = Key.generateKey(List.of(KeyUsage.EXCHANGE));
            Key serverKey = Key.generateKey(List.of(KeyUsage.EXCHANGE));
            Key shared1 = clientKey.generateSharedSecret(serverKey.publicCopy(), List.of(KeyUsage.ENCRYPT));
            Key shared2 = clientKey.publicCopy().generateSharedSecret(serverKey, List.of(KeyUsage.ENCRYPT));
            assertTrue(shared1.hasUsage(KeyUsage.ENCRYPT));
            assertTrue(shared2.hasUsage(KeyUsage.ENCRYPT));
            assertEquals(shared1.getSecret(), shared2.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void generateSharedSecretTest2() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjQ2ODE0OFoiLCJrZXkiOiIyREJWdDhWOWhSOTU0Mjl5MWdja3lXaVBoOXhVRVBxb2hFUTFKQjRnSjlodmpaV1hheE0zeWVURXYiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMyWiIsInB1YiI6IjJEQlZ0bk1aUDc5aEpWTUpwVnlIR29rRU1QWEM2cXkzOHNoeVRIaEpBekY5TlVRdlFmUWRxNGRjMyJ9";
            String encodedShared = "DSTN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
            Key clientKey = Item.importFromEncoded(encodedClient);
            assertNotNull(clientKey);
            Key serverKey = Item.importFromEncoded(encodedServer);
            assertNotNull(serverKey);
            Key shared = clientKey.generateSharedSecret(serverKey, List.of(KeyUsage.ENCRYPT));
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void generateSharedSecretTest3() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDE1MloiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMxNloiLCJrZXkiOiIyREJWdDhWOWJ4R2pGS0xoa2FodEo0UUtRc3F6Y1ZjNGFqeWNxSnQ4eFZQTlZkYnBveHBLdkFZaUoiLCJwdWIiOiIyREJWdG5NWlA3OWhKVk1KcFZ5SEdva0VNUFhDNnF5MzhzaHlUSGhKQXpGOU5VUXZRZlFkcTRkYzMifQ";
            String encodedShared = "DSTN.2bLW8dmYQr4jrLSKiTLggLU1cbVMkmK1uUChchxYzAMC9fshCG";
            Key clientKey = Item.importFromEncoded(encodedClient);
            assertNotNull(clientKey);
            Key serverKey = Item.importFromEncoded(encodedServer);
            assertNotNull(serverKey);
            Key shared = clientKey.generateSharedSecret(serverKey, List.of(KeyUsage.ENCRYPT));
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void encryptTest1() {
        try {
            String data = "Racecar is racecar backwards.";
            Key key = Key.generateKey(List.of(KeyUsage.ENCRYPT));
            byte[] cipherText = Dime.crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Dime.crypto.decrypt(cipherText, key);
            assertNotNull(plainText);
            assertEquals(data, new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void encryptTest2() {
        try {
            String data = "Racecar is racecar backwards.";
            String encoded = "Di:KEY.eyJ1aWQiOiI3ZmM1ODcxMi0xYzY3LTQ4YmItODRmMS1kYjlkOGYyZWM2ZTMiLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjI2OjU4LjQ2ODQ2MloiLCJrZXkiOiIyMmV0WkFOOHlQZmtNQkxpem83WE13S0Zrd29UTVJDeXpNdG9uMVV6RUVRODZqWGRjQmtTdTV0d1EifQ";
            Key key = Item.importFromEncoded(encoded);
            byte[] cipherText = Dime.crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Dime.crypto.decrypt(cipherText, key);
            assertNotNull(plainText);
            assertEquals(data, new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
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
            assertEquals("Racecar is racecar backwards.", new String(plainText, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void generateHashTest1() {
        try {
            String ref = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            byte[] data = "Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8);
            byte[] hash = Dime.crypto.generateHash(data);
            assertNotNull(hash);
            String hex = Utility.toHex(hash);
            assertEquals(ref, hex);
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void cryptoPlatformExchangeTest1() {
        try {
            Key clientKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
            Key serverKey = Item.importFromEncoded("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");
            byte[] shared1 = Dime.crypto.generateSharedSecret(clientKey, serverKey.publicCopy(), List.of(KeyUsage.ENCRYPT));
            byte[] shared2 = Dime.crypto.generateSharedSecret(clientKey.publicCopy(), serverKey, List.of(KeyUsage.ENCRYPT));
            String hash1 = Utility.toHex(shared1);
            String hash2 = Utility.toHex(shared2);
            assertEquals("8c0c2c98d5839bc59a61fa0bea987aea6f058c08c214ab65d1a87e2a7913cea9", hash1);
            assertEquals(hash1, hash2);
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

}
