//
//  StandardSuite.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import com.goterl.lazysodium.SodiumJava;
import io.dimeformat.Item;
import io.dimeformat.Key;
import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.Utility;
import io.dimeformat.exceptions.CryptographyException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Implements the NaCl (salt) cryptographic algorithm suite defined in the DiME data format specification.
 */
class NaClSuite implements ICryptoSuite {

    static final String SUITE_NAME = "NaCl";

    public String getName() {
        return _suiteName;
    }

    public NaClSuite(String name) {
        this._sodium = new SodiumJava();
        this._suiteName = name;
    }

    public String generateKeyName(Key key) {
        // This only supports key identifier for public keys, may be different for other crypto suites
        byte[] bytes = key.getKeyBytes(Claim.PUB);
        if (bytes != null && bytes.length > 0) {
            try {
                byte[] hash = hash(bytes);
                byte[] name = Utility.subArray(hash, 0, 8); // First 8 bytes are used as an identifier
                return Utility.toHex(name);
            } catch (CryptographyException e) { /* ignored */ }
        }
        return null;
    }

    public byte[] generateSignature(Item item, Key key) throws CryptographyException {
        String thumbprint = item.generateThumbprint(false, this._suiteName);
        if (thumbprint != null && !thumbprint.isEmpty()) {
            byte[] signature = new byte[NaClSuite.NBR_SIGNATURE_BYTES];
            byte[] data = thumbprint.getBytes(StandardCharsets.UTF_8);
            int result = this._sodium.crypto_sign_detached(signature,
                    null,
                    data,
                    data.length,
                    key.getKeyBytes(Claim.KEY));
            if (result != 0) {
                throw new CryptographyException("Failed to generate signature, error code returned: " + result);
            }
            return signature;
        }
        throw new IllegalArgumentException("Failed to generate signature, item thumbprint was null or empty.");
    }

    public boolean verifySignature(Item item, byte[] signature, Key key) throws CryptographyException {
        String thumbprint =item.generateThumbprint(false, this._suiteName);
        if (thumbprint != null && !thumbprint.isEmpty()) {
            byte[] data = thumbprint.getBytes(StandardCharsets.UTF_8);
            return (this._sodium.crypto_sign_verify_detached(signature,
                    data,
                    data.length,
                    key.getKeyBytes(Claim.PUB)) == 0);
        }
        throw new IllegalArgumentException("Failed to generate signature, item thumbprint was null or empty.");
    }

    public Key generateKey(List<KeyCapability> capabilities) throws CryptographyException {
        if (capabilities == null || capabilities.size() != 1) { throw new IllegalArgumentException("Unable to generate, invalid key capabilities requested."); }
        KeyCapability firstUse = capabilities.get(0);
        if (firstUse == KeyCapability.ENCRYPT) {
            byte[] secretKey = new byte[NaClSuite.NBR_S_KEY_BYTES];
            this._sodium.crypto_secretbox_keygen(secretKey);
            return new Key(capabilities, secretKey, null, this._suiteName);
        } else {
            byte[] publicKey = new byte[NaClSuite.NBR_A_KEY_BYTES];
            byte[] secretKey;
            switch (capabilities.get(0)) {
                case SIGN:
                    secretKey = new byte[NaClSuite.NBR_A_KEY_BYTES * 2];
                    this._sodium.crypto_sign_keypair(publicKey, secretKey);
                    break;
                case EXCHANGE:
                    secretKey = new byte[NaClSuite.NBR_A_KEY_BYTES];
                    this._sodium.crypto_kx_keypair(publicKey, secretKey);
                    break;
                default:
                    throw new CryptographyException("Unable to generate keypair for key type " + capabilities + ".");
            }
            return new Key(capabilities, secretKey, publicKey, this._suiteName);
        }
    }

    public Key generateSharedSecret(Key clientKey, Key serverKey, List<KeyCapability> capabilities) throws CryptographyException {
        if (!capabilities.contains(KeyCapability.ENCRYPT)) { throw new IllegalArgumentException("Unable to generate, key capability for shared secret must be ENCRYPT."); }
        if (capabilities.size() > 1) { throw new IllegalArgumentException("Unable to generate, key capability for shared secret may only be ENCRYPT."); }
        byte[][] rawClientKeys = new byte[][] { clientKey.getKeyBytes(Claim.KEY), clientKey.getKeyBytes(Claim.PUB) };
        byte[][] rawServerKeys = new byte[][] { serverKey.getKeyBytes(Claim.KEY), serverKey.getKeyBytes(Claim.PUB) };
        byte[] shared = new byte[NaClSuite.NBR_X_KEY_BYTES];
        if (rawClientKeys[0] != null && rawClientKeys.length == 2) { // has both private and public key
            byte[] secret = Utility.combine(rawClientKeys[0], rawClientKeys[1]);
            if (this._sodium.crypto_kx_client_session_keys(shared, null, rawClientKeys[1], secret, rawServerKeys[1]) != 0) {
                throw new CryptographyException("Unable to generate, cryptographic operation failed.");
            }
        } else if (rawServerKeys[0] != null && rawServerKeys.length == 2) { // has both private and public key
            if (this._sodium.crypto_kx_server_session_keys(null, shared, rawServerKeys[1], rawServerKeys[0], rawClientKeys[1]) != 0) {
                throw new CryptographyException("Unable to generate, cryptographic operation failed.");
            }
        } else {
            throw new CryptographyException("Unable to generate, invalid keys provided.");
        }
        return new Key(capabilities, shared, null, this._suiteName);
    }

    public byte[] encrypt(byte[] data, Key key) throws CryptographyException {
        byte[] nonce = Utility.randomBytes(NaClSuite.NBR_NONCE_BYTES);
        if (nonce.length > 0) {
            byte[] cipherText = new byte[NaClSuite.NBR_MAC_BYTES + data.length];
            if (this._sodium.crypto_secretbox_easy(cipherText, data, data.length, nonce, key.getKeyBytes(Claim.KEY)) != 0) {
                throw new CryptographyException("Cryptographic operation failed.");
            }
            return Utility.combine(nonce, cipherText);
        }
        throw new CryptographyException("Unable to generate sufficient nonce.");

    }

    public byte[] decrypt(byte[] data, Key key) throws CryptographyException {
        byte[] nonce = Utility.subArray(data, 0, NaClSuite.NBR_NONCE_BYTES);
        byte[] bytes = Utility.subArray(data, NaClSuite.NBR_NONCE_BYTES);
        byte[] plain = new byte[bytes.length - NaClSuite.NBR_MAC_BYTES];
        int result = this._sodium.crypto_secretbox_open_easy(plain, bytes, bytes.length, nonce, key.getKeyBytes(Claim.KEY));
        if (result != 0) {
            throw new CryptographyException("Cryptographic operation failed (" + result + ").");
        }
        return plain;
    }

    public String generateHash(byte[] data) throws CryptographyException {
        return Utility.toHex(hash(data));
    }

    public String encodeKeyBytes(byte[] rawKey, Claim claim) {
        return Utility.toBase64(rawKey);
    }

    public byte[] decodeKeyBytes(String encodedKey, Claim claim) {
        return Utility.fromBase64(encodedKey);
    }

    /// PROTECTED ///

    protected static final int NBR_SIGNATURE_BYTES = 64;
    protected static final int NBR_A_KEY_BYTES = 32;
    protected static final int NBR_S_KEY_BYTES = 32;
    protected static final int NBR_X_KEY_BYTES = 32;
    protected static final int NBR_NONCE_BYTES = 24;
    protected static final int NBR_MAC_BYTES = 16;
    protected static final int NBR_HASH_BYTES = 32;

    protected final SodiumJava _sodium;
    protected final String _suiteName;

    /// PRIVATE ///

    private byte[] hash(byte[] data) throws CryptographyException {
        byte[] hash = new byte[NaClSuite.NBR_HASH_BYTES];
        if (this._sodium.crypto_generichash(hash, hash.length, data, data.length, null, 0) != 0) {
            throw new CryptographyException("Cryptographic operation failed.");
        }
        return hash;
    }

}
