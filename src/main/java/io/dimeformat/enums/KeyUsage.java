//
//  KeyUsage.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Defines different types of cryptographic keys.
 * Used for header information in keys and when generating new keys.
 */
public enum KeyUsage {

    /**
     * Undefined usage of the key (should not happen).
     */
    UNDEFINED,
    /**
     * Key type for asymmetric key used for signing.
     */
    SIGN,
    /**
     * Key type for asymmetric keys used for key exchange (agreement).
     */
    EXCHANGE,
    /**
     * Key type for symmetric keys used for encryption.
     */
    ENCRYPT;

    /**
     * An intermediate method to convert legacy KeyType to KeyUsage. Should only be used for legacy keys.
     * @param type The KeyType to convert.
     * @return Equivalent KeyUsage.
     */
    @Deprecated
    public static KeyUsage fromKeyType(KeyType type) {
        switch (type) {
            case IDENTITY: return KeyUsage.SIGN;
            case EXCHANGE: return KeyUsage.EXCHANGE;
            case ENCRYPTION: return KeyUsage.ENCRYPT;
            case AUTHENTICATION:
            case UNDEFINED:
            default:
                return KeyUsage.UNDEFINED;
        }
    }

}
