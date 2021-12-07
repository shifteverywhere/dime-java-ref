//
//  CryptoTest.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyType;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {

    @Test
    void generateSignatureTest1() {
        try {
            String data = "Racecar is racecar backwards.";
            Key key = Crypto.generateKey(KeyType.IDENTITY);
            String sig = Crypto.generateSignature(data, key);
            Crypto.verifySignature(data, sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest2() {
        try {
            String sig = "Ey5hGXAXFq1WgVS0bhzmx4qfT6VdsTQtZDF4PSRTBAcWZmO/2jhFPmV2YEy5bIA8PHDwRHXtbdU5Psi3ln7cBA";
            String encoded = "Di:KEY.eyJ1aWQiOiJmNjYxMGUyNS1jYTA1LTQzMWItODhlZS1iYzczNmZiNWQxZmUiLCJwdWIiOiIyVERYZG9Odm9NZFd4VGh4Z2FxVG5McTl0aFdWYXZFeUFWaUx2ekNrc2VxMWtlRDNrOGJ4UkY2cVciLCJpYXQiOiIyMDIxLTEyLTAyVDIwOjQ4OjAxLjEyMDUxOFoiLCJrZXkiOiJTMjFUWlNMQmFjYXhURVVBVFExVG91dENIRkI1NFA2R25vTTNLU0hXMUpvNTgxZUZzalZYajZEWHBYMjdKTFRCSFVQaWNmbUVKZ2FxNnhaeEoxeVN3TldieTQ2cUdzQ3hrUmpCIn0";
            Key key = Item.importFromEncoded(encoded);
            Crypto.verifySignature("Racecar is racecar backwards.", sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateGenerateSharedSecretTest1() {
        try {
            Key clientKey = Key.generateKey(KeyType.EXCHANGE);
            Key serverKey = Key.generateKey(KeyType.EXCHANGE);
            Key shared1 = Crypto.generateSharedSecret(clientKey, serverKey.publicCopy());
            Key shared2 = Crypto.generateSharedSecret(clientKey.publicCopy(), serverKey);
            assertEquals(KeyType.ENCRYPTION, shared1.getKeyType());
            assertEquals(KeyType.ENCRYPTION, shared2.getKeyType());
            assertEquals(shared1.getSecret(), shared2.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void generateGenerateSharedSecretTest2() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjQ2ODE0OFoiLCJrZXkiOiIyREJWdDhWOWhSOTU0Mjl5MWdja3lXaVBoOXhVRVBxb2hFUTFKQjRnSjlodmpaV1hheE0zeWVURXYiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMyWiIsInB1YiI6IjJEQlZ0bk1aUDc5aEpWTUpwVnlIR29rRU1QWEM2cXkzOHNoeVRIaEpBekY5TlVRdlFmUWRxNGRjMyJ9";
            String encodedShared = "22etZANAXYDE4m15ZtofRnMn81dUwBzN1s7QcoKF2yo8my84Hd5vecQUe";
            Key clientKey = Item.importFromEncoded(encodedClient);
            Key serverKey = Item.importFromEncoded(encodedServer);
            Key shared = Crypto.generateSharedSecret(clientKey, serverKey);
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void generateGenerateSharedSecretTest3() {
        try {
            String encodedClient = "Di:KEY.eyJ1aWQiOiI1ODc1YWNjZS01OTE5LTQwMzEtOWY2MS0zMzg4NGZmOTRiY2EiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDE1MloiLCJwdWIiOiIyREJWdG5NYUZ6ZkpzREIyTGtYS2hjV3JHanN2UG1TMXlraXdCTjVvZXF2eExLaDRBMllIWFlUc1EifQ";
            String encodedServer = "Di:KEY.eyJ1aWQiOiJkNDQ5ZTYxMC1jZDhmLTQ0OTYtOTAxYS02N2ZmNDVjNmNkNzAiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjA4OjAzLjUyNDMxNloiLCJrZXkiOiIyREJWdDhWOWJ4R2pGS0xoa2FodEo0UUtRc3F6Y1ZjNGFqeWNxSnQ4eFZQTlZkYnBveHBLdkFZaUoiLCJwdWIiOiIyREJWdG5NWlA3OWhKVk1KcFZ5SEdva0VNUFhDNnF5MzhzaHlUSGhKQXpGOU5VUXZRZlFkcTRkYzMifQ";
            String encodedShared = "22etZANAXYDE4m15ZtofRnMn81dUwBzN1s7QcoKF2yo8my84Hd5vecQUe";
            Key clientKey = Item.importFromEncoded(encodedClient);
            Key serverKey = Item.importFromEncoded(encodedServer);
            Key shared = Crypto.generateSharedSecret(clientKey, serverKey);
            assertEquals(encodedShared, shared.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void encryptTest1() {
        try {
            String data = "Racecar is racecar backwards.";
            Key key = Key.generateKey(KeyType.ENCRYPTION);
            byte[] cipherText = Crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Crypto.decrypt(cipherText, key);
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
            byte[] cipherText = Crypto.encrypt(data.getBytes(StandardCharsets.UTF_8), key);
            assertNotNull(cipherText);
            byte[] plainText = Crypto.decrypt(cipherText, key);
            assertNotNull(plainText);
            String p = new String(plainText, StandardCharsets.UTF_8);
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
             byte[] plainText = Crypto.decrypt(Utility.fromBase64(cipherText), key);
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
            byte[] hash = Crypto.generateHash(data);
            assertNotNull(hash);
            String hex = Utility.toHex(hash);
            assertEquals(ref, hex);
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

}