//
//  CryptoDDCS.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.crypto;

import com.goterl.lazysodium.SodiumJava;
import io.dimeformat.Utility;
import io.dimeformat.enums.KeyUsage;
import io.dimeformat.exceptions.DimeCryptographicException;

import java.util.List;

/**
 * Implements the Dime standard cryptographic suite (DSTD).
 */
public class CryptoSuiteStandard implements ICryptoSuite {

    public String getName() {
        return "DSTD";
    }

    public CryptoSuiteStandard() {
        this.sodium = new SodiumJava();
    }

    public byte[] generateSignature(byte[] data, byte[] key) throws DimeCryptographicException {
        byte[] signature = new byte[CryptoSuiteStandard.NBR_SIGNATURE_BYTES];
        if (this.sodium.crypto_sign_detached(signature, null, data, data.length, key) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed.");
        }
        return signature;
    }

    public boolean verifySignature(byte[] data, byte[] signature, byte[] key) {
        return (this.sodium.crypto_sign_verify_detached(signature, data, data.length, key) == 0);
    }

    public byte[] generateSymmetricKey(List<KeyUsage> usage) throws DimeCryptographicException {
        byte[] secretKey = new byte[CryptoSuiteStandard.NBR_S_KEY_BYTES];
        this.sodium.crypto_secretbox_keygen(secretKey);
        return secretKey;
    }

    public byte[][] generateAsymmetricKeys(List<KeyUsage> usage) throws DimeCryptographicException {
        if (usage == null || usage.size() != 1) { throw new IllegalArgumentException("Invalid key usage requested."); }
        byte[] publicKey = new byte[CryptoSuiteStandard.NBR_A_KEY_BYTES];
        byte[] secretKey;
        switch (usage.get(0)) {
            case SIGN:
                secretKey = new byte[CryptoSuiteStandard.NBR_A_KEY_BYTES * 2];
                this.sodium.crypto_sign_keypair(publicKey, secretKey);
                break;
            case EXCHANGE:
                secretKey = new byte[CryptoSuiteStandard.NBR_A_KEY_BYTES];
                this.sodium.crypto_kx_keypair(publicKey, secretKey);
                break;
            default:
                throw new DimeCryptographicException("Unable to generate keypair for key type " + usage + ".");
        }
        return new byte[][] { secretKey, publicKey };
    }

    public byte[] generateSharedSecret(byte[][] clientKey, byte[][] serverKey, List<KeyUsage> usage) throws DimeCryptographicException {
        if (!usage.contains(KeyUsage.ENCRYPT)) { throw new IllegalArgumentException("Key usage for shared secret must be ENCRYPT"); }
        if (usage.size() > 1) { throw new IllegalArgumentException("Key usage for shared secret may only be ENCRYPT"); }
        byte[] shared = new byte[CryptoSuiteStandard.NBR_X_KEY_BYTES];
        if (clientKey[0] != null && clientKey.length == 2) { // has both private and public key
            byte[] secret = Utility.combine(clientKey[0], clientKey[1]);
            if (this.sodium.crypto_kx_client_session_keys(shared, null, clientKey[1], secret, serverKey[1]) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed.");
            }
        } else if (serverKey[0] != null && serverKey.length ==2) { // has both private and public key
            if (this.sodium.crypto_kx_server_session_keys(null, shared, serverKey[1], serverKey[0], clientKey[1]) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed.");
            }
        } else {
            throw new DimeCryptographicException("Unable to generate shared secret.");
        }
        return shared;
    }

    public byte[] encrypt(byte[] data, byte[] key) throws DimeCryptographicException {
        byte[] nonce = Utility.randomBytes(CryptoSuiteStandard.NBR_NONCE_BYTES);
        if (nonce.length > 0) {
            byte[] cipherText = new byte[CryptoSuiteStandard.NBR_MAC_BYTES + data.length];
            if (this.sodium.crypto_secretbox_easy(cipherText, data, data.length, nonce, key) != 0) {
                throw new DimeCryptographicException("Cryptographic operation failed.");
            }
            return Utility.combine(nonce, cipherText);
        }
        throw new DimeCryptographicException("Unable to generate sufficient nonce.");

    }

    public byte[] decrypt(byte[] data, byte[] key) throws DimeCryptographicException {
        byte[] nonce = Utility.subArray(data, 0, CryptoSuiteStandard.NBR_NONCE_BYTES);
        byte[] bytes = Utility.subArray(data, CryptoSuiteStandard.NBR_NONCE_BYTES);
        byte[] plain = new byte[bytes.length - CryptoSuiteStandard.NBR_MAC_BYTES];
        if (this.sodium.crypto_secretbox_open_easy(plain, bytes, bytes.length, nonce, key) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed.");
        }
        return plain;
    }

    public byte[] generateHash(byte[] data) throws DimeCryptographicException {
        byte[] hash = new byte[CryptoSuiteStandard.NBR_HASH_BYTES];
        if (this.sodium.crypto_generichash(hash, hash.length, data, data.length, null, 0) != 0) {
            throw new DimeCryptographicException("Cryptographic operation failed.");
        }
        return hash;
    }

    /// PRIVATE ///

    private static final int NBR_SIGNATURE_BYTES = 64;
    private static final int NBR_A_KEY_BYTES = 32;
    private static final int NBR_S_KEY_BYTES = 32;
    private static final int NBR_X_KEY_BYTES = 32;
    private static final int NBR_NONCE_BYTES = 24;
    private static final int NBR_MAC_BYTES = 16;
    private static final int NBR_HASH_BYTES = 32;

    private final SodiumJava sodium;

}
