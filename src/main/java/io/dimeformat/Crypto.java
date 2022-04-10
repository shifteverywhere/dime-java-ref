//
//  Crypto.java
//  Di:ME - Data Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
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

/**
 * Cryptographic helper methods, which also abstracts the rest of the implementation from any 
 * underlying cryptographic library used.
 */
public final class Crypto {

    /// PUBLIC ///

    /**
     * Generates a cryptographic signature from a data string.
     * @param data The string to sign.
     * @param key The key to use for the signature.
     * @return The signature that was generated, encoded in Base 64.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static String generateSignature(String data, Key key) throws DimeCryptographicException {
        if (data == null || data.length() == 0) { throw new IllegalArgumentException("Unable to sign, data must not be null or of length zero."); }
        if (key == null || key.getRawSecret() == null) { throw new IllegalArgumentException("Unable to sign, key must not be null."); }
        if (key.getKeyType() != IDENTITY) { throw new IllegalArgumentException("Unable to sign, wrong key type provided, got: " + key.getKeyType() + ", expected: " + IDENTITY + "."); }
        byte[] signature = new byte[Crypto.NBR_SIGNATURE_BYTES];
        byte[] message = data.getBytes(StandardCharsets.UTF_8);
        byte[] secret = key.getRawSecret();
        if (Crypto.sodium.crypto_sign_detached(signature, null, message, message.length, secret) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed (C1001).");
        }
        return Utility.toBase64(signature);
    }

    /**
     * Verifies a cryptographic signature for a data string.
     * @param data The string that should be verified with the signature.
     * @param signature The signature that should be verified.
     * @param key The key that should be used for the verification.
     * @throws DimeIntegrityException If something goes wrong.
     */
    public static void verifySignature(String data, String signature, Key key) throws DimeIntegrityException {
        if (key == null) { throw new IllegalArgumentException("Unable to verify signature, key must not be null."); }
        if (data == null || data.length() == 0) { throw new IllegalArgumentException("Data must not be null, or of length zero."); }
        if (signature == null || signature.length() == 0) { throw new IllegalArgumentException("Signature must not be null, or of length zero."); }
        if (key.getRawPublic() == null) { throw new IllegalArgumentException("Unable to sign, public key in key must not be null."); }
        if (key.getKeyType() != IDENTITY) { throw new IllegalArgumentException("Unable to sign, wrong key type provided, got: " + key.getKeyType() + ", expected: " + IDENTITY + "."); }
        byte[] rawSignature = Utility.fromBase64(signature);
        byte[] message = data.getBytes(StandardCharsets.UTF_8);
        byte[] publicKey = key.getRawPublic();
        if (Crypto.sodium.crypto_sign_verify_detached(rawSignature, message, message.length, publicKey) != 0) {
            throw new DimeIntegrityException("Unable to verify signature (C1002).");
        }
    }

    /**
     * Generates a cryptographic key of a provided type.
     * @param type The type of the key to generate.
     * @return The generated key.
     */
    public static Key generateKey(KeyType type) {
        if (type == ENCRYPTION || type == AUTHENTICATION) {
            byte[] secretKey = new byte[Crypto.NBR_S_KEY_BYTES];
            Crypto.sodium.crypto_secretbox_keygen(secretKey);
            return new Key(UUID.randomUUID(), type, secretKey, null);
        } else {
            byte[] publicKey = new byte[Crypto.NBR_A_KEY_BYTES];
            byte[] secretKey;
            switch (type) {
                case IDENTITY:
                    secretKey = new byte[Crypto.NBR_A_KEY_BYTES * 2];
                    Crypto.sodium.crypto_sign_keypair(publicKey, secretKey);
                    break;
                case EXCHANGE:
                    secretKey = new byte[Crypto.NBR_A_KEY_BYTES];
                    Crypto.sodium.crypto_kx_keypair(publicKey, secretKey);
                    break;
                default:
                    throw new IllegalArgumentException("Unknown or unsupported key type.");
            }
            return new Key(UUID.randomUUID(), type, secretKey, publicKey);
        }
    }

    /**
     * Generates a shared secret from two keys of type EXCHANGE. The initiator of the key exchange is always the
     * server and the receiver of the key exchange is always the client (no matter on which side this method is
     * called). The returned key will be of type ENCRYPTION.
     * @param clientKey The client key to use (the receiver of the exchange).
     * @param serverKey The server key to use (the initiator of the exchange).
     * @return The generated shared secret key.
     * @throws DimeKeyMismatchException If provided keys are of the wrong type.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public static Key generateSharedSecret(Key clientKey, Key serverKey) throws DimeKeyMismatchException, DimeCryptographicException {
        if (clientKey.getVersion() != serverKey.getVersion()) { throw new DimeKeyMismatchException("Unable to generate shared key, source keys from different versions."); }
        if (clientKey.getKeyType() != EXCHANGE || serverKey.getKeyType() != EXCHANGE) { throw new DimeKeyMismatchException("Keys must be of type 'Exchange'."); }
        byte[] shared = new byte[Crypto.NBR_X_KEY_BYTES];
        if (clientKey.getRawSecret() != null) {
            byte[] secret = Utility.combine(clientKey.getRawSecret(), clientKey.getRawPublic());
            if (sodium.crypto_kx_client_session_keys(shared, null, clientKey.getRawPublic(), secret, serverKey.getRawPublic()) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed. C1003)");
            }
        } else if (serverKey.getRawSecret() != null) {
            if (sodium.crypto_kx_server_session_keys(null, shared, serverKey.getRawPublic(), serverKey.getRawSecret(), clientKey.getRawPublic()) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed. C1004)");
            }
        } else {
            throw new DimeKeyMismatchException("Invalid keys provided.");
        }
        return new Key(UUID.randomUUID(), KeyType.ENCRYPTION, shared, null);
    }

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param plainText The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static byte[] encrypt(byte[] plainText, Key key) throws DimeCryptographicException {
        if (plainText == null || plainText.length == 0) { throw new IllegalArgumentException("Plain text to encrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        byte[] nonce = Utility.randomBytes(Crypto.NBR_NONCE_BYTES);
        if (nonce.length > 0) {
            byte[] cipherText = new byte[Crypto.NBR_MAC_BYTES + plainText.length];
            if (Crypto.sodium.crypto_secretbox_easy(cipherText, plainText, plainText.length, nonce, key.getRawSecret()) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed. (C1005)");
            }
            return Utility.combine(nonce, cipherText);
        }
        throw new DimeCryptographicException("Unable to generate sufficient nonce. (C1006)");
    }

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param cipherText The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The decrypted plain text.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static byte[] decrypt(byte[] cipherText, Key key) throws DimeCryptographicException {
        if (cipherText == null ||cipherText.length == 0) { throw new IllegalArgumentException("Cipher text to decrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        byte[] nonce = Utility.subArray(cipherText, 0, Crypto.NBR_NONCE_BYTES);
        byte[] bytes = Utility.subArray(cipherText, Crypto.NBR_NONCE_BYTES);
        byte[] plainText = new byte[bytes.length - Crypto.NBR_MAC_BYTES];
        if (Crypto.sodium.crypto_secretbox_open_easy(plainText, bytes, bytes.length, nonce, key.getRawSecret()) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed. (C1007)");
        }
        return plainText;
    }

    /**
     * Generates a secure hash of a byte array.
     * @param data The data that should be hashed.
     * @return The generated secure hash.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static byte[] generateHash(byte[] data) throws DimeCryptographicException {
        byte[] hash = new byte[Crypto.NBR_HASH_BYTES];
        if (Crypto.sodium.crypto_generichash(hash, hash.length, data, data.length, null, 0) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed. C1008)");
        }
        return hash;
    }

    /// PRIVATE ///

    private static final int NBR_SIGNATURE_BYTES = 64;
    private static final int NBR_MAC_BYTES = 16;
    private static final int NBR_HASH_BYTES = 32;
    private static final int NBR_A_KEY_BYTES = 32;
    private static final int NBR_S_KEY_BYTES = 32;
    private static final int NBR_X_KEY_BYTES = 32;
    private static final int NBR_NONCE_BYTES = 24;
    private static final SodiumJava sodium = new SodiumJava();

    private Crypto() {
        throw new IllegalStateException("Not intended to be instantiated.");
    }


}
