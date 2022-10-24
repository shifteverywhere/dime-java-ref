//
//  ICrypto.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.enums.KeyCapability;
import java.util.List;

/**
 * An interface that classes need to implement to provide cryptographic services.
 */
public interface ICryptoSuite {

    /**
     * Array position for a secret key. This includes private keys and encryption keys.
     */
    int SECRET_KEY_INDEX = 0;

    /**
     * Array position for a public key.
     */
    int PUBLIC_KEY_INDEX = 1;

    /**
     * Returns the name of the cryptographic suite, usually a short series of letters, i.e. STN for the standard
     * Dime cryptography suite.
     * @return Identifier of the cryptographic suite.
     */
    String getName();

    /**
     * Generates a unique name for a key. The generated name is not sensitive and may be distributed without
     * compromising the key.
     * @param key The key to generate a name for.
     * @return A unique name.
     */
    byte[] generateKeyName(byte[][] key);

    /**
     * Generates a cryptographic signature from a data byte array using the provided key.
     * @param data The data that should be signed.
     * @param key The key to use when signing the data.
     * @return The signature as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] generateSignature(byte[] data, byte[] key) throws CryptographyException;

    /**
     * Verifies a cryptographic signature for a data byte array using the provided key.
     * @param data The data that the signature should be verified towards.
     * @param signature The signature to verify.
     * @param key The key to use when verifying.
     * @return True is verified successfully, false if not.
     */
    boolean verifySignature(byte[] data, byte[] signature, byte[] key);

    /**
     * Generates a cryptographic key for the provided usage, if possible.
     * @param capabilities The intended capabilities of the generated key, i.e. {#{@link KeyCapability#SIGN}}.
     * @return The generated key.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[][] generateKey(List<KeyCapability> capabilities) throws CryptographyException;

    /**
     *  Generates a shared secret from two keys or key pars. These keys must have {#{@link KeyCapability#EXCHANGE}}
     *  listed as a capability. The server/issuer of a key exchange is always the initiator and the client/audience is
     *  always the receiver (no matter on which side this method is called).
     * @param clientKey The key or key pair from the client (usually the audience).
     * @param serverKey The key or key pair from the server (usually the issuer).
     * @param capabilities The intended capabilities of the generated key, i.e. {#{@link KeyCapability#ENCRYPT}}.
     * @return The generated shared key.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] generateSharedSecret(byte[][] clientKey, byte[][] serverKey, List<KeyCapability> capabilities) throws CryptographyException;

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param data The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] encrypt(byte[] data, byte[] key) throws CryptographyException;

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param data The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The plain text as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] decrypt(byte[] data, byte[] key) throws CryptographyException;

    /**
     * Generates a secure hash digest of the provided data.
     * @param data The data that should be hashed.
     * @return The hash digest of the provided data, encoded as a string.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    String generateHash(byte[] data) throws CryptographyException;

    /**
     * Encodes a key from a byte array to a string.
     * @param key The key to encode.
     * @return The encoded key.
     */
    String encodeKey(byte[] key);

    /**
     * Decodes an encoded key to a byte array.
     * @param encodedKey The encoded key.
     * @return The decoded key.
     */
    byte[] decodeKey(String encodedKey);

}
