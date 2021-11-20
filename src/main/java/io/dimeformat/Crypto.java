//
//  Crypto.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeIntegrityException;
import io.dimeformat.exceptions.DimeKeyMismatchException;
import com.goterl.lazysodium.SodiumJava;
import static io.dimeformat.enums.KeyType.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public class Crypto {

    /// PUBLIC ///

    public static String generateSignature(String data, Key key) throws DimeCryptographicException {
        if (key == null || key.getRawSecret() == null) { throw new IllegalArgumentException("Unable to sign, key must not be null."); }
        if (key.getKeyType() != IDENTITY) { throw new IllegalArgumentException("Unable to sign, wrong key type provided, got: " + key.getKeyType() + ", expected: " + IDENTITY + "."); }
        byte[] signature = new byte[Crypto._NBR_SIGNATURE_BYTES];
        byte[] message = data.getBytes(StandardCharsets.UTF_8);
        byte[] secret = key.getRawSecret();
        if (Crypto.sodium.crypto_sign_detached(signature, null, message, message.length, secret) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed (C1001).");
        }
        return Utility.toBase64(signature);
    }

    public static void verifySignature(String data, String signature, Key key) throws DimeIntegrityException {
        if (key == null) { throw new IllegalArgumentException("Unable to verify signature, key must not be null."); }
        if (data == null) { throw new IllegalArgumentException("Data must not be null."); }
        if (signature == null) { throw new IllegalArgumentException("Signature must not be null."); }
        if (key.getRawPublic() == null) { throw new IllegalArgumentException("Unable to sign, public key in keybox must not be null."); }
        if (key.getKeyType() != IDENTITY) { throw new IllegalArgumentException("Unable to sign, wrong key type provided, got: " + key.getKeyType() + ", expected: " + IDENTITY + "."); }
        byte[] rawSignature = Utility.fromBase64(signature);
        byte[] message = data.getBytes(StandardCharsets.UTF_8);
        byte[] publicKey = key.getRawPublic();
        if (Crypto.sodium.crypto_sign_verify_detached(rawSignature, message, message.length, publicKey) != 0) {
            throw new DimeIntegrityException("Unable to verify signature (C1002).");
        }
    }

    public static io.dimeformat.Key generateKey(KeyType type) {
        if (type == ENCRYPTION || type == AUTHENTICATION) {
            byte[] secretKey = new byte[Crypto._NBR_S_KEY_BYTES];
            Crypto.sodium.crypto_secretbox_keygen(secretKey);
            return new Key(UUID.randomUUID(), type, secretKey, null);
        } else {
            byte[] publicKey = new byte[Crypto._NBR_A_KEY_BYTES];
            byte[] secretKey = new byte[Crypto._NBR_A_KEY_BYTES * 2];
            switch (type) {
                case IDENTITY:
                    Crypto.sodium.crypto_sign_keypair(publicKey, secretKey);
                    break;
                case EXCHANGE:
                    Crypto.sodium.crypto_kx_keypair(publicKey, secretKey);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown or unsupported key type.");
            }
            return new Key(UUID.randomUUID(), type, secretKey, publicKey);
        }
    }

    public static Key generateSharedSecret(Key clientKey, Key serverKey, byte[] salt, byte[] info) throws DimeKeyMismatchException, DimeCryptographicException {
        if (clientKey.getVersion() != serverKey.getVersion()) { throw new DimeKeyMismatchException("Unable to generate shared key, source keys from diffrent versions."); }
        if (clientKey.getKeyType() != EXCHANGE || serverKey.getKeyType() != EXCHANGE) { throw new DimeKeyMismatchException("Keys must be of type 'Exchange'."); }
        byte[] shared = new byte[Crypto._NBR_X_KEY_BYTES];
        if (clientKey.getRawSecret() != null) {
            if (sodium.crypto_kx_client_session_keys(shared, null, clientKey.getRawPublic(), clientKey.getRawSecret(), serverKey.getRawPublic()) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed. C1003)");
            }
        } else if (serverKey.getRawSecret() != null) {
            if (sodium.crypto_kx_server_session_keys(null, shared, serverKey.getRawPublic(), serverKey.getRawSecret(), clientKey.getRawPublic()) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed. C1004)");
            }
        } else {
            throw new DimeKeyMismatchException("Invalid keys provided.");
        }
        System.out.println("shared: " + Utility.toHex(shared));
        System.out.println("---");
        return new Key(UUID.randomUUID(), KeyType.ENCRYPTION, shared, null);
    }

    public static byte[] encrypt(byte[] plainText, Key key) throws DimeCryptographicException {
        if (plainText == null || plainText.length == 0) { throw new IllegalArgumentException("Plain text to encrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        byte[] nonce = Utility.randomBytes(Crypto._NBR_NONCE_BYTES);
        byte[] cipherText = new byte[Crypto._NBR_MAC_BYTES + plainText.length];
        if (Crypto.sodium.crypto_secretbox_easy(cipherText, plainText, plainText.length, nonce, key.getRawSecret()) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed. C1005)"); 
        }
        return Utility.combine(nonce, cipherText);
    }

    public static byte[] decrypt(byte[] cipherText, Key key) throws DimeCryptographicException {
        if (cipherText == null ||cipherText.length == 0) { throw new IllegalArgumentException("Cipher text to decrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        byte[] nonce = Utility.subArray(cipherText, 0, Crypto._NBR_NONCE_BYTES);
        byte[] bytes = Utility.subArray(cipherText, Crypto._NBR_NONCE_BYTES);
        byte[] plainText = new byte[bytes.length - Crypto._NBR_MAC_BYTES];
        if (Crypto.sodium.crypto_secretbox_open_easy(plainText, bytes, bytes.length, nonce, key.getRawSecret()) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed. C1007)");
        }
        return plainText;
    }

    public static byte[] generateHash(byte[] data) throws DimeCryptographicException {
        byte[] hash = new byte[Crypto._NBR_HASH_BYTES];
        if (Crypto.sodium.crypto_generichash(hash, hash.length, data, data.length, null, 0) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed. C1008)");
        }
        return hash;
    }

    /// PRIVATE ///

    private static final int _NBR_SIGNATURE_BYTES = 64;
    private static final int _NBR_MAC_BYTES = 16;
    private static final int _NBR_HASH_BYTES = 32;
    private static final int _NBR_A_KEY_BYTES = 32;
    private static final int _NBR_S_KEY_BYTES = 32;
    private static final int _NBR_X_KEY_BYTES = 32;
    private static final int _NBR_NONCE_BYTES = 24;
    private static final SodiumJava sodium = new SodiumJava();

}
