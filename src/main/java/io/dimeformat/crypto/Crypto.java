//
//  Crypto.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import io.dimeformat.Key;
import io.dimeformat.Utility;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeIntegrityException;
import java.nio.charset.StandardCharsets;
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
     * Set the default cryptographic suite name. This will be used when no suite is specificed for cryptographic
     * operations. It can be queried through {@link Crypto#getDefaultSuiteName()}. This will be set by default to
     * Dime Standard Cryptographic Suite (DSTD).
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


    public String generateKeyIdentifier(Key key) {
        if (key == null) { throw new IllegalArgumentException("Unable to generate key identifier, key must not be null."); }
        try {
            ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
            byte[] id = impl.generateKeyIdentifier(new byte[][] { key.getKeyBytes(Claim.KEY), key.getKeyBytes(Claim.PUB) });
            if (id != null) {
                return Utility.toHex(id);
            }
        } catch (DimeCryptographicException e) { /* ignored */ }
        return null;
    }

    /**
     * Generates a cryptographic signature from a data string.
     * @param data The string to sign.
     * @param key The key to use for the signature.
     * @return The signature that was generated, encoded in Base 64.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] generateSignature(String data, Key key) throws DimeCryptographicException {
        if (data == null || data.length() == 0) { throw new IllegalArgumentException("Unable to sign, data must not be null or of length zero."); }
        if (key == null || key.getSecret() == null) { throw new IllegalArgumentException("Unable to sign, secret key in key must not be null."); }
        if (!key.hasUse(Key.Use.SIGN)) { throw new IllegalArgumentException("Provided key does not specify SIGN usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.generateSignature(data.getBytes(StandardCharsets.UTF_8), key.getKeyBytes(Claim.KEY));
    }

    /**
     * Verifies a cryptographic signature for a data string.
     * @param data The string that should be verified with the signature.
     * @param signature The signature that should be verified.
     * @param key The key that should be used for the verification.
     * @throws DimeIntegrityException If something goes wrong.
     */
    public void verifySignature(String data, byte[] signature, Key key) throws DimeCryptographicException, DimeIntegrityException {
        if (key == null) { throw new IllegalArgumentException("Unable to verify signature, key must not be null."); }
        if (data == null || data.length() == 0) { throw new IllegalArgumentException("Data must not be null, or of length zero."); }
        if (signature == null || signature.length == 0) { throw new IllegalArgumentException("Signature must not be null, or of length zero."); }
        if (key.getPublic() == null) { throw new IllegalArgumentException("Unable to verify, public key in key must not be null."); }
        if (!key.hasUse(Key.Use.SIGN)) { throw new IllegalArgumentException("Provided key does not specify SIGN usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        if (!impl.verifySignature(data.getBytes(StandardCharsets.UTF_8), signature, key.getKeyBytes(Claim.PUB))) {
            throw new DimeIntegrityException("Unable to verify signature (C1002).");
        }
    }

    /**
     * Generates a cryptographic key of a provided type. This will use the cryptographic suite that is set as the
     * default.
     * @param use The use of the key to generate.
     * @return The generated key.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[][] generateKey(List<Key.Use> use) throws DimeCryptographicException {
        return generateKey(use, getDefaultSuiteName());
    }

    /**
     * Generates a cryptographic key of a provided type.
     * @param use The use of the key to generate.
     * @param suiteName The cryptographic suite that should be used when generating the key.
     * @return The generated key.
     */
    public byte[][] generateKey(List<Key.Use> use, String suiteName) throws DimeCryptographicException {
        if (use == null || use.size() == 0) { throw new DimeCryptographicException("Key usage must not be null or empty."); }
        ICryptoSuite impl = getCryptoSuite(suiteName);
        return impl.generateKey(use);
    }

    /**
     * Generates a shared secret from two keys of type EXCHANGE. The initiator of the key exchange is always the
     * server and the receiver of the key exchange is always the client (no matter on which side this method is
     * called).
     * @param clientKey The client key to use (the receiver of the exchange).
     * @param serverKey The server key to use (the initiator of the exchange).
     * @return The generated shared secret key.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public byte[] generateSharedSecret(Key clientKey, Key serverKey, List<Key.Use> use) throws DimeCryptographicException {
        if (!clientKey.getUse().contains(Key.Use.EXCHANGE) || !serverKey.getUse().contains(Key.Use.EXCHANGE)) { throw new IllegalArgumentException("Provided keys do not specify EXCHANGE usage."); }
        if (!clientKey.getCryptoSuiteName().equals(serverKey.getCryptoSuiteName())) { throw  new IllegalArgumentException(("Client key and server key are not generated using the same cryptographic suite")); }
        ICryptoSuite impl = getCryptoSuite(clientKey.getCryptoSuiteName());
        byte[][] rawClientKeys = new byte[][] { clientKey.getKeyBytes(Claim.KEY), clientKey.getKeyBytes(Claim.PUB) };
        byte[][] rawServerKeys = new byte[][] { serverKey.getKeyBytes(Claim.KEY), serverKey.getKeyBytes(Claim.PUB) };
        return impl.generateSharedSecret(rawClientKeys, rawServerKeys, use);
    }

    /**
     * Encrypts a plain text byte array using the provided key.
     * @param plainText The byte array to encrypt.
     * @param key The key to use for the encryption.
     * @return The encrypted cipher text.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] encrypt(byte[] plainText, Key key) throws DimeCryptographicException {
        if (plainText == null || plainText.length == 0) { throw new IllegalArgumentException("Plain text to encrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        if (!key.hasUse(Key.Use.ENCRYPT)) { throw new DimeCryptographicException("Provided key does not specify ENCRYPT usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.encrypt(plainText, key.getKeyBytes(Claim.KEY));
    }

    /**
     * Decrypts a cipher text byte array using the provided key.
     * @param cipherText The byte array to decrypt.
     * @param key The key to use for the decryption.
     * @return The decrypted plain text.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] decrypt(byte[] cipherText, Key key) throws DimeCryptographicException {
        if (cipherText == null ||cipherText.length == 0) { throw new IllegalArgumentException("Cipher text to decrypt must not be null and not have a length of 0."); }
        if (key == null) { throw new IllegalArgumentException("Key must not be null."); }
        if (!key.hasUse(Key.Use.ENCRYPT)) { throw new DimeCryptographicException("Provided key does not specify ENCRYPT usage."); }
        ICryptoSuite impl = getCryptoSuite(key.getCryptoSuiteName());
        return impl.decrypt(cipherText, key.getKeyBytes(Claim.KEY));
    }

    /**
     * Generates a secure hash of a byte array. This will use the cryptographic suite that is set as the default.
     * @param data The data that should be hashed.
     * @return The generated secure hash.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] generateHash(byte[] data) throws DimeCryptographicException {
        return generateHash(data, getDefaultSuiteName());
    }

    /**
     * Generates a secure hash of a byte array.
     * @param data The data that should be hashed.
     * @param suiteName The cryptographic suite that should be used to generate the hash.
     * @return The generated secure hash.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] generateHash(byte[] data, String suiteName) throws DimeCryptographicException {
        ICryptoSuite crypto = getCryptoSuite(suiteName);
        return crypto.generateHash(data);
    }

    /**
     * Registers a cryptographic suite. The provided name must be unique, it should also be short as it will be
     * included with the encoded key, uppercase is recommended. If a cryptographic suite is already register with the
     * provided name then IllegalArgumentException will be thrown.
     * @param impl The implementation instance of ICryptoSuite.
     * @param name A unique name for the suite.
     */
    public void registerCryptoSuite(ICryptoSuite impl, String name) {
        if (impl == null) { throw new IllegalArgumentException("Instance of ICrypto implementation must not be null."); }
        if (name == null || name.isEmpty()) { throw new IllegalArgumentException("Name of cryptographic suite must not be null or empty."); }
        if (_suiteMap == null) {
            _suiteMap = new HashMap<>();
        } else if (_suiteMap.containsKey(name)) {
            throw new IllegalArgumentException("Cryptographic suite already exists with name: " + name);
        }
        _suiteMap.put(name, impl);
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

    private ICryptoSuite getCryptoSuite(String name) throws DimeCryptographicException {
        if (_suiteMap == null || _suiteMap.isEmpty()) {
            throw new DimeCryptographicException("Unable to perform cryptographic operation, no suites registered.");
        }
        ICryptoSuite impl = _suiteMap.get(name);
        if (impl == null) {
            throw new DimeCryptographicException("Unable to find cryptographic suite with name: " + name);
        }
        return impl;
    }

}
