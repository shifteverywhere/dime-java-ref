//
//  ICrypto.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import io.dimeformat.Item;
import io.dimeformat.Key;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.enums.KeyCapability;
import java.util.List;

/**
 * An interface that classes need to implement to provide cryptographic services.
 */
public interface ICryptoSuite {

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
    String generateKeyName(Key key);

    /**
     * Generates a cryptographic signature from an item using the provided key.
     * @param item The item that should be signed.
     * @param key The key to use when signing the data.
     * @return The signature as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] generateSignature(Item item, Key key) throws CryptographyException;

    /**
     * Verifies a cryptographic signature for an item using the provided key.
     * @param item The item that should be verified towards the signature.
     * @param signature The raw signature to verify, as a byte-array.
     * @param key The key to use when verifying the signature.
     * @return True is verified successfully, false if not.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    boolean verifySignature(Item item, byte[] signature, Key key) throws CryptographyException;

    /**
     * Generates a cryptographic key for the provided usage, if possible.
     * @param capabilities The intended capabilities of the generated key, i.e. {#{@link KeyCapability#SIGN}}.
     * @return The generated key.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    Key generateKey(List<KeyCapability> capabilities) throws CryptographyException;

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
    Key generateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities) throws CryptographyException;

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param data The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] encrypt(byte[] data, Key key) throws CryptographyException;

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param data The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The plain text as a byte array.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    byte[] decrypt(byte[] data, Key key) throws CryptographyException;

    /**
     * Generates a secure hash digest of the provided data.
     * @param data The data that should be hashed.
     * @return The hash digest of the provided data, encoded as a string.
     * @throws CryptographyException If any cryptographic operations goes wrong.
     */
    String generateHash(byte[] data) throws CryptographyException;

    /**
     * Encodes a key from a byte-array to a string.
     * @param rawKey The raw key byte-array to encode.
     * @param claim The name of the claim to encode the key for, should be {@link Claim#KEY} or {@link Claim#PUB}
     * @return The encoded key.
     */
    String encodeKeyBytes(byte[] rawKey, Claim claim);

    /**
     * Decodes an encoded key to a byte array.
     * @param encodedKey The encoded key.
     * @param claim The name of the claim to decode the key for, should be {@link Claim#KEY} or {@link Claim#PUB}
     * @return The decoded key.
     */
    byte[] decodeKeyBytes(String encodedKey, Claim claim);

}
