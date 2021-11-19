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
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class CryptoTest {

    @Test
    void generateSignatureTest1() {
        try {
            String data = "Racecar is racecar backwards.";
            Key key = Crypto.generateKey(Profile.UNO, KeyType.IDENTITY);
            String sig = Crypto.generateSignature(data, key);
            Crypto.verifySignature(data, sig, key);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void generateGenerateSharedSecretTest1() {
        try {
            Key clientKey = Key.generateKey(KeyType.EXCHANGE);
            Key serverKey = Key.generateKey(KeyType.EXCHANGE);
            Key shared1 = Crypto.generateSharedSecret(clientKey, serverKey.publicCopy(), null, null);
            Key shared2 = Crypto.generateSharedSecret(clientKey.publicCopy(), serverKey, null, null);
            assertEquals(KeyType.ENCRYPTION, shared1.getKeyType());
            assertEquals(KeyType.ENCRYPTION, shared2.getKeyType());
            assertEquals(shared1.getSecret(), shared2.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

    @Test
    void encrypt() {
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
    void generateHashTest1() {
        try {
            String ref = "b9f050dd8bfbf027ea9fc729e9e764fda64c2bca20030a5d25264c35c486d892";
            byte[] data = "Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8);
            byte[] hash = Crypto.generateHash(Profile.UNO, data);
            assertNotNull(hash);
            String hex = Utility.toHex(hash);
            assertEquals(ref, hex);
        } catch (Exception e) {
            fail("Unexpected exception thrown.");
        }
    }

}