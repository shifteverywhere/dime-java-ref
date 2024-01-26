//
//  Crypto.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import io.dimeformat.*;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.enums.KeyCapability;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

/**
 * Cryptographic helper methods, which also abstracts the rest of the implementation from any 
 * underlying cryptographic library used.
 */
public final class Crypto {

    /// PUBLIC ///

    /**
     * Default constructor.
     */
    public Crypto() {
        registerCryptoSuite(new NaClSuite(NaClSuite.SUITE_NAME));
        registerCryptoSuite(new LegacySuite(LegacySuite.LEGACY_DSC_SUITE));
        registerCryptoSuite(new LegacySuite(LegacySuite.LEGACY_STN_SUITE));
        _defaultSuiteName = NaClSuite.SUITE_NAME;
    }

    /**
     * Set the default cryptographic suite name. This will be used when no suite is specified for cryptographic
     * operations. It can be queried through {@link Crypto#getDefaultSuiteName()}. This will be set by default to
     * Dime Standard Cryptographic Suite (STN).
     * @param name The name of the suite to set as the default.
     */
    public synchronized void setDefaultSuiteName(String name) {
        if (_suiteMap == null) { throw new IllegalStateException("Unable to set default cryptographic suite name, no suites registered."); }
        if (!_suiteMap.containsKey(name)) { throw new IllegalArgumentException("No cryptographic suite registered for name: " + name); }
        _defaultSuiteName = name;
    }

    /**
     * Returns the name of the cryptographic suite that is set as the default.
     * @return Name of default cryptographic suite.
     */
    public synchronized String getDefaultSuiteName() {
        return _defaultSuiteName;
    }

    /**
     * Will generate a unique key name from the provided key. This will be used to extract which key was used to
     * create a signature. How a key name is generated is specific to the cryptographic suite used.
     * @param key The key to generate a name for.
     * @return A key name, as a String.
     */
    public String generateKeyName(Key key) {
        if (key == null) { throw new IllegalArgumentException("Unable to generate key identifier, key must not be null."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.generateKeyName(key);
    }

    /**
     * Generates a cryptographic signature from a provided item and key.
     * @param item The item that should be signed.
     * @param key The key that should be used to sign the item.
     * @return The signature that was generated.
     * @throws CryptographyException If something goes wrong.
     */
    public Signature generateSignature(Item item, Key key) throws CryptographyException {
        if (item == null) { throw new IllegalArgumentException("Unable to generate signature, item to sign must not be null."); }
        if (key == null || key.getSecret() == null) { throw new IllegalArgumentException("Unable to generate signature, key or secret key must not be null."); }
        if (!key.hasCapability(KeyCapability.SIGN)) { throw new IllegalArgumentException("Unable to generate signature, provided key does not specify 'SIGN' capability."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        byte[] bytes = impl.generateSignature(item, key);
        String name = item.isLegacy() ? null : generateKeyName(key);
        return new Signature(bytes, name);
    }

    /**
     * Verifies a cryptographic signature of an item using provided signature and key.
     * @param item The item to verify the signature with.
     * @param signature The signature to verify with.
     * @param key The key to use when verifying.
     * @return True if verified successfully, false otherwise.
     * @throws CryptographyException If something goes wrong.
     */
    public boolean verifySignature(Item item, Signature signature, Key key) throws CryptographyException {
        if (item == null) { throw new IllegalArgumentException("Unable to verify signature, item to sign must not be null."); }
        if (signature == null) { throw new IllegalArgumentException("Unable to verify signature, item to sign must not be null."); }
        if (key == null || key.getPublic() == null) { throw new IllegalArgumentException("Unable to verify signature, key or public key must not be null."); }
        if (!key.hasCapability(KeyCapability.SIGN)) { throw new IllegalArgumentException("Unable to verify signature, provided key does not specify 'SIGN' capability."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.verifySignature(item,
                signature.getBytes(),
                key);
    }

    /**
     * Generates a cryptographic key of a provided type. This will use the cryptographic suite that is set as the
     * default.
     * @param capabilities The capabilities of the key to generate.
     * @return The generated key.
     * @throws CryptographyException If something goes wrong.
     */
    public Key generateKey(List<KeyCapability> capabilities) throws CryptographyException {
        return generateKey(capabilities, getDefaultSuiteName());
    }

    /**
     * Generates a cryptographic key of a provided type.
     * @param capabilities The capabilities of the key to generate.
     * @param suiteName The cryptographic suite that should be used when generating the key.
     * @return The generated key.
     * @throws CryptographyException If anything goes wrong.
     */
    public Key generateKey(List<KeyCapability> capabilities, String suiteName) throws CryptographyException {
        if (capabilities == null || capabilities.isEmpty()) { throw new CryptographyException("Key usage must not be null or empty."); }
        ICryptoSuite impl = getCryptoSuite(suiteName);
        return impl.generateKey(capabilities);
    }

    /**
     * Generates a shared secret from two keys with use 'Exchange'. The initiator of the key exchange is always the
     * server and the receiver of the key exchange is always the client (no matter on which side this method is
     * called).
     * @param clientKey The client key to use (the receiver of the exchange).
     * @param serverKey The server key to use (the initiator of the exchange).
     * @param capabilities The capabilities that should be specified for the generated key.
     * @return The generated shared secret key.
     * @throws CryptographyException If anything goes wrong.
     */
    public Key generateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities) throws CryptographyException {
        if (!clientKey.hasCapability(KeyCapability.EXCHANGE) || !serverKey.hasCapability(KeyCapability.EXCHANGE)) { throw new IllegalArgumentException("Provided keys do not specify EXCHANGE usage."); }
        if (!clientKey.getCryptoSuiteName().equals(serverKey.getCryptoSuiteName())) { throw  new IllegalArgumentException(("Client key and server key are not generated using the same cryptographic suite")); }
        ICryptoSuite impl = getCryptoSuite(clientKey.getCryptoSuiteName());
        return impl.generateSharedSecret(clientKey, serverKey, capabilities);
    }

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param plainText The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text.
     * @throws CryptographyException If something goes wrong.
     */
    public byte[] encrypt(byte[] plainText, Key key) throws CryptographyException {
        if (plainText == null || plainText.length == 0) { throw new IllegalArgumentException("Plain text to encrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        if (!key.hasCapability(KeyCapability.ENCRYPT)) { throw new CryptographyException("Provided key does not specify ENCRYPT usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.encrypt(plainText, key);
    }

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param cipherText The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The decrypted plain text.
     * @throws CryptographyException If something goes wrong.
     */
    public byte[] decrypt(byte[] cipherText, Key key) throws CryptographyException {
        if (cipherText == null ||cipherText.length == 0) { throw new IllegalArgumentException("Cipher text to decrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        if (!key.hasCapability(KeyCapability.ENCRYPT)) { throw new CryptographyException("Provided key does not specify ENCRYPT usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.decrypt(cipherText, key);
    }

    /**
     * Generates a secure hash of a byte array. This will use the cryptographic suite that is set as the default.
     * @param data The data that should be hashed.
     * @return The generated secure hash, encoded as a string
     * @throws CryptographyException If something goes wrong.
     */
    public String generateHash(byte[] data) throws CryptographyException {
        return generateHash(data, getDefaultSuiteName());
    }

    /**
     * Generates a secure hash of a byte array.
     * @param data The data that should be hashed.
     * @param suiteName The cryptographic suite that should be used to generate the hash.
     * @return The generated secure hash, encoded as a string
     * @throws CryptographyException If something goes wrong.
     */
    public String generateHash(byte[] data, String suiteName) throws CryptographyException {
        ICryptoSuite crypto = getCryptoSuite(suiteName);
        return crypto.generateHash(data);
    }

    /**
     * Encodes a key from a byte array to a string. The encoding format is determined by the cryptographic suite
     * specified.
     * @param rawKey The raw key bytes to encode.
     * @param claim The name of the claim to encode the key for, must be {@link Claim#KEY} or {@link Claim#PUB}.
     * @param suiteName The cryptographic suite to use.
     * @return The encoded key.
     */
    public String encodeKeyBytes(byte[] rawKey, Claim claim, String suiteName) {
        ICryptoSuite crypto = getCryptoSuite(suiteName);
        return crypto.encodeKeyBytes(rawKey, claim);
    }

    /**
     * Decodes an encoded key to a byte array. The encoded format must match the cryptographic suite specified to be
     * successful.
     * @param encodedKey The encoded raw key bytes.
     * @param claim The name of the claim to decode the key for, should be {@link Claim#KEY} or {@link Claim#PUB}
     * @param suiteName The cryptographic suite to use.
     * @return The decoded key.
     */
    public byte[] decodeKeyBytes(String encodedKey, Claim claim, String suiteName) {
        ICryptoSuite crypto = getCryptoSuite(suiteName);
        return crypto.decodeKeyBytes(encodedKey, claim);
    }

    /**
     * Registers a cryptographic suite. If a cryptographic suite is already register with the same name as the provided
     * cryptographic suite then IllegalArgumentException will be thrown.
     * @param impl The implementation instance of ICryptoSuite.
     */
    public void registerCryptoSuite(ICryptoSuite impl) {
        if (impl == null) { throw new IllegalArgumentException("Instance of ICrypto implementation must not be null."); }
        if (_suiteMap == null) {
            _suiteMap = new HashMap<>();
        } else if (_suiteMap.containsKey(impl.getName())) {
            throw new IllegalArgumentException("Cryptographic suite already exists with name: " + impl.getName());
        }
        _suiteMap.put(impl.getName(), impl);
    }

    /**
     * Indicates if a cryptographic suite with the provided name is supported (and registered).
     * @param name The name of the cryptographic suite to check for.
     * @return True if supported, false if not.
     */
    public boolean hasCryptoSuite(String name) {
        if (_suiteMap == null) { return false; }
        return _suiteMap.containsKey(name);
    }

    /**
     * Returns a set of the names of all registered cryptographic suites.
     * @return Set of registered cryptographic suites, names only.
     */
    public Set<String> allCryptoSuites() {
        if (_suiteMap == null) { return null; }
        return _suiteMap.keySet();
    }

    /// PRIVATE ///

    private HashMap<String, ICryptoSuite> _suiteMap;
    private String _defaultSuiteName;

    private ICryptoSuite getCryptoSuite(String name) {
        if (_suiteMap == null || _suiteMap.isEmpty()) {
            throw new IllegalStateException("Unable to perform cryptographic operation, no suites registered.");
        }
        ICryptoSuite impl = _suiteMap.get(name);
        if (impl == null) {
            throw new IllegalArgumentException("Unable to find cryptographic suite with name: " + name);
        }
        return impl;
    }

}
