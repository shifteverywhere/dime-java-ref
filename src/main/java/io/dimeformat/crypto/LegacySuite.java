//
//  StandardSuite.java
//  DiME - Data Identity Message Envelope
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

/**
 * Implements the legacy suits used in previous specifications of DiME, i.e. STN and DSC.
 * @deprecated Will be removed in future versions, use NaCl instead (default).
 */
@Deprecated
class LegacySuite extends NaClSuite {

    static final String LEGACY_DSC_SUITE = "DSC"; // Base64 encoding
    static final String LEGACY_STN_SUITE = "STN"; // Base58 encoding

    public LegacySuite(String name) {
        super(name);
    }

    @Override
    public byte[] generateSignature(Item item, Key key) throws CryptographyException {
        byte[] signature = new byte[NaClSuite.NBR_SIGNATURE_BYTES];
        byte[] data = item.rawEncoded(false);
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

    @Override
    public boolean verifySignature(Item item, byte[] signature, Key key) throws CryptographyException {
        byte[] keyBytes = key.getKeyBytes(Claim.PUB);
        if (keyBytes == null || keyBytes.length == 0) { throw new IllegalArgumentException("Unable to verify signature, missing public key."); }
        byte[] data = item.rawEncoded(false);
        return (this._sodium.crypto_sign_verify_detached(signature,
                data,
                data.length,
                key.getKeyBytes(Claim.PUB)) == 0);
    }

    @Override
    public String encodeKeyBytes(byte[] rawKey, Claim claim) {
        if (_suiteName.equals(LegacySuite.LEGACY_STN_SUITE)) {
            return Base58.encode(rawKey);
        }
        return super.encodeKeyBytes(rawKey, claim);
    }

    @Override
    public byte[] decodeKeyBytes(String encodedKey, Claim claim) {
        if (_suiteName.equals(LegacySuite.LEGACY_STN_SUITE)) {
            return Base58.decode(encodedKey);
        }
        return super.decodeKeyBytes(encodedKey, claim);
    }

}
