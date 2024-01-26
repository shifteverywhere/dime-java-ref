//
//  CryptoTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
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
        assertTrue(Dime.crypto.hasCryptoSuite("NaCl")); //default
        assertTrue(Dime.crypto.hasCryptoSuite("DSC"));  // legacy base64
        assertTrue(Dime.crypto.hasCryptoSuite("STN"));  // legacy base58
        assertFalse(Dime.crypto.hasCryptoSuite("NSA")); // non-existing
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
    void defaultSuiteNameTest1() {
       assertNotNull(Dime.crypto.getDefaultSuiteName());
       assertEquals("NaCl", Dime.crypto.getDefaultSuiteName());
    }

    @Test
    void defaultSuiteNameTest2() {
        Dime.crypto.setDefaultSuiteName("DSC");
        assertEquals("DSC", Dime.crypto.getDefaultSuiteName());
        Dime.crypto.setDefaultSuiteName("NaCl");
        assertEquals("NaCl", Dime.crypto.getDefaultSuiteName());
    }

    @Test
    void defaultSuiteNameTest3() {
        try {
            Dime.crypto.setDefaultSuiteName("NSA"); // non-existing
            fail("Exception not thrown.");
        } catch (IllegalArgumentException e) { /* all is well */ }
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
            String name = "40950cea47a2b319";
            String encoded = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTo1NToyNC43NzI5NDMzWiIsImtleSI6Ik5hQ2wuRXdxVWU4M1JERitkNlpGaU1ZQ2NTNHg4OFZtZTUxS3JvVTlId3U4b1l3MCIsInB1YiI6Ik5hQ2wuemxuQ1BZTTl5SFprOWpTdGhxOXZVQWtYTy9pR2dFcmhaY040bzJoWXFUYyIsInVpZCI6IjY4ZDk2NWUzLTAxNmEtNGI2Yy05NzUyLTFmYzlhNzdhNjc1MSJ9";
            Key key = Item.importFromEncoded(encoded);
            assertEquals(name, Dime.crypto.generateKeyName(key));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            Signature signature = Dime.crypto.generateSignature(key, key);
            assertTrue(Dime.crypto.verifySignature(key, signature, key));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSignatureTest2() {
        try {
            String encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjExOjIyLjk1MzQ1NDZaIiwia2V5IjoiTmFDbC5RdS9KVmNjTk5hMlBPa0owMmoxOVNLNHlMam1mZzJyMlpDQzhrTi9LZUIxTDBYWVFDenpnRm40L1QvQjZ5d3NZVEFTNVdzQUk0b0NLdlNvZlN4Sm8rdyIsInB1YiI6Ik5hQ2wuUzlGMkVBczg0QlorUDAvd2Vzc0xHRXdFdVZyQUNPS0FpcjBxSDBzU2FQcyIsInVpZCI6ImQ0YzBmYjkwLWE1OTEtNDk2YS04OWNjLTAyNTlhYjhiMjU5NSJ9";
            Key key = Item.importFromEncoded(encoded);
            Signature signature = new Signature(
                    Utility.fromHex("c447e712b0cfd384a2d0e80ec0006962057d76406683dd9587b0bd08b09389d24cc8ba13d0d4c3b92a315602e83c04d5a48229f2c6d428183d51193b119b9a01"),
                    null);
            assertTrue(Dime.crypto.verifySignature(key, signature, key));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateSharedSecretTest1() {
        try {
            Key clientKey = Key.generateKey(KeyCapability.EXCHANGE);
            Key serverKey = Key.generateKey(KeyCapability.EXCHANGE);
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
            String encodedClient = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTozMjozNC44NTYyMjM1WiIsImtleSI6Ik5hQ2wuU0ZWQUpZc1BESzBZS3NTbGx3Qm9LLzByU0FPRUY5aXB3RHJvdU9iMEt6WSIsInB1YiI6Ik5hQ2wuQm45WkV1S01BTXNpU2daL2NxYzhpTFg1QkIvMVhBSGJiRTBCVWNuYjVBYyIsInVpZCI6ImI4MzgzMGJlLWNkYWUtNGFjYi04YWEwLWVjYzUwYWIwZTBhMCJ9";
            String encodedServer = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyNC0wMS0yNlQwOTozMjozNC44NTY5MjgzWiIsInB1YiI6Ik5hQ2wuNU0rZFQ4U2lGS0x3YTdOdXRDRWhLWkFFcnlhamtheFFqK1ZteFM4MTNXRSIsInVpZCI6IjVjMmI4OWIwLWY4ZDItNDEwNS1iNzc1LTQzOGY4MTIwZDBhMiJ9";
            String encodedShared = "NaCl.hTxsOaGVldUkwgSGLUMnxUdalTRpU7PulenQUIL+7o8";
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
            Key key = Key.generateKey(KeyCapability.ENCRYPT);
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
            String encoded = "Di:KEY.eyJjYXAiOlsiZW5jcnlwdCJdLCJpYXQiOiIyMDI0LTAxLTI2VDA4OjQ4OjA5LjM4MjU1MjNaIiwia2V5IjoiTmFDbC5xaFV5Y0RDeUF3MkJiSmxWK3lSQ1pBZXRoNWl1YVo2WU15azJrK3NOYUNFIiwidWlkIjoiNWI5YTQ1ZjgtNzQzYi00MTFmLWJhODItMzA4YTgxNjdkYmM4In0";
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
            String cipherText = "p5UDu1/yciMaoMYE2P6yN/giWOu5zCwmvL89eBMrbgeIymscVK4pVaWdfJ3i8OZ7cMiJ+/feDfF5GG9Y539jKnwDB3Vv";
            String encoded = "Di:KEY.eyJjYXAiOlsiZW5jcnlwdCJdLCJpYXQiOiIyMDI0LTAxLTI2VDA4OjQ4OjA5LjM4MjU1MjNaIiwia2V5IjoiTmFDbC5xaFV5Y0RDeUF3MkJiSmxWK3lSQ1pBZXRoNWl1YVo2WU15azJrK3NOYUNFIiwidWlkIjoiNWI5YTQ1ZjgtNzQzYi00MTFmLWJhODItMzA4YTgxNjdkYmM4In0";
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
            Key naclKey = Key.generateKey(KeyCapability.SIGN);
            assertNotNull(naclKey);
            assertEquals(suiteName, naclKey.getCryptoSuiteName());
            Utility.fromBase64(naclKey.getSecret().substring(suiteName.length() + 1));
            Utility.fromBase64(naclKey.getPublic().substring(suiteName.length() + 1));
            String exported = naclKey.exportToEncoded();
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
            String suiteName = "DSC";
            Key dscKey = Key.generateKey(List.of(KeyCapability.SIGN), Dime.NO_EXPIRATION, null, null, suiteName);
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

}
