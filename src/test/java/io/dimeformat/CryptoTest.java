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

import io.dimeformat.enums.Claim;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import io.dimeformat.enums.KeyCapability;
import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {

    @Test
    void hasCryptoSuiteTest1() {
        assertTrue(Dime.crypto.hasCryptoSuite("NaCl"));
        assertFalse(Dime.crypto.hasCryptoSuite("NSA"));
    }

    @Test
    void allCryptoSuitesTest1() {
        Set<String> suiteNames = Dime.crypto.allCryptoSuites();
        assertNotNull(suiteNames);
        assertEquals(3, suiteNames.size());
        assertTrue(suiteNames.contains("NaCl"));
        assertTrue(suiteNames.contains("DSC"));
        assertTrue(suiteNames.contains("STN"));
    }

    @Test
    void setDefaultSuiteNameTest1() {
        try { Dime.crypto.setDefaultSuiteName("NSA"); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        Dime.crypto.setDefaultSuiteName("STN");
    }

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
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Signature signature = Dime.crypto.generateSignature(key, key);
            Dime.crypto.verifySignature(key, signature, key);

            String sig = Utility.toBase64(signature.getBytes());
            String k = key.exportToEncoded();

            int i = 0;

        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest2() {
        try {
            String encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIzLTAyLTIzVDEzOjI3OjQ3LjE4MTM2NzcwOFoiLCJrZXkiOiJOYUNsLmRvVzlxVVlhUVZ5a1dmaEhkMFNqVzlIT1Frd0ZtaXQvY2tBQWtkNlNHZy9MTDZ1djJ5a1N4YUVRTmlPMmE3anhmaVdvU1g1N1hqR0hvWU8wN3V6WnlnIiwicHViIjoiTmFDbC55eStycjlzcEVzV2hFRFlqdG11NDhYNGxxRWwrZTE0eGg2R0R0TzdzMmNvIiwidWlkIjoiMDNhNWE4OTAtNTFkZS00N2U0LTg1MGMtYzhlOTY2MmY4ZjAxIn0";
            Key key = Item.importFromEncoded(encoded);
            Signature signature = new Signature(Utility.fromBase64("cjk/O3yicD1F5Y53XuEshnOe5EsNaRurQHA7ynC7p3jSRNEEoe8ZlZuOKB3qNO6uQfdgkWonzFjoyuWjtEX8Cg"),null);
            Dime.crypto.verifySignature(key, signature, key);
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
            String hash = Dime.crypto.generateHash(data);
            assertNotNull(hash);
            assertEquals(ref, hash);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void suiteTest1() {
        try {
            String suiteName = Dime.crypto.getDefaultSuiteName();
            Key dscKey = Key.generateKey(KeyCapability.SIGN);
            assertNotNull(dscKey);
            assertEquals(suiteName, dscKey.getCryptoSuiteName());
            Utility.fromBase64(dscKey.getSecret().substring(suiteName.length() + 1));
            Utility.fromBase64(dscKey.getPublic().substring(suiteName.length() + 1));
            String exported = dscKey.exportToEncoded();
            assertNotNull(exported);
            String claims = exported.split("\\.")[1];
            JSONObject json = new JSONObject(new String(Utility.fromBase64(claims)));
            assertNotNull(json);
            assertTrue(json.has(Claim.KEY.name().toLowerCase()));
            assertTrue(json.has(Claim.PUB.name().toLowerCase()));
            assertTrue(json.getString("key").startsWith(suiteName + "."));
            assertTrue(json.getString("pub").startsWith(suiteName + "."));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void suiteTest2() {
        try {
            Key stnKey = Key.generateKey(List.of(KeyCapability.SIGN), Dime.NO_EXPIRATION, null, null, "STN");
            assertNotNull(stnKey);
            assertEquals("STN", stnKey.getCryptoSuiteName());
            Base58.decode(stnKey.getSecret().substring(4));
            Base58.decode(stnKey.getPublic().substring(4));
            String exported = stnKey.exportToEncoded();
            assertNotNull(exported);
            String claims = exported.split("\\.")[1];
            JSONObject json = new JSONObject(new String(Utility.fromBase64(claims)));
            assertNotNull(json);
            assertTrue(json.has("key"));
            assertTrue(json.has("pub"));
            assertTrue(json.getString("key").startsWith("STN."));
            assertTrue(json.getString("pub").startsWith("STN."));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
