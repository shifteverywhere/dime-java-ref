//
//  ICrypto.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import io.dimeformat.enums.KeyUsage;
import io.dimeformat.exceptions.DimeCryptographicException;

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
     * Returns the name of the cryptographic suite, usually a short series of letters, i.e. DDCS for Dime Default
     * Cryptography Suite.
     * @return
     */
    String getName();

    byte[] generateKeyIdentifier(byte[][] key);

    /**
     * Generates a cryptographic signature from a data byte array using the provided key.
     * @param data The data that should be signed.
     * @param key The key to use when signing the data.
     * @return The signature as a byte array.
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[] generateSignature(byte[] data, byte[] key) throws DimeCryptographicException;

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
     * @param usage The intended usage of the generated key, i.e. {#{@link KeyUsage#SIGN}}.
     * @return The generated key.
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[][] generateKey(List<KeyUsage> usage) throws DimeCryptographicException;

    /**
     *  Generates a shared secret from two keys or key pars. These keys must have {#{@link KeyUsage#EXCHANGE}} listad as
     *  usage. The server/issuer of a key exchange is always the initiator and the client/audience is always the
     *  receiver (no matter on which side this method is called).
     * @param clientKey The key or key pair from the client (usually the audience).
     * @param serverKey The key or key pair from the server (usually the issuer).
     * @param usage The intended usage of the generated key, i.e. {#{@link KeyUsage#ENCRYPT}}.
     * @return The generated shared key.
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[] generateSharedSecret(byte[][] clientKey, byte[][] serverKey, List<KeyUsage> usage) throws DimeCryptographicException;

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param data The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text as a byte array.
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[] encrypt(byte[] data, byte[] key) throws DimeCryptographicException;

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param data The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The plain text as a byte array.
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[] decrypt(byte[] data, byte[] key) throws DimeCryptographicException;

    /**
     *
     * @param data
     * @return
     * @throws DimeCryptographicException If any cryptographic operations goes wrong.
     */
    byte[] generateHash(byte[] data) throws DimeCryptographicException;

}
