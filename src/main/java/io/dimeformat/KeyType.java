//
//  KeyType.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

/**
 * Defines different types of cryptographic keys.
 */
public enum KeyType {

    /**
     * Undefined usage of the key (should not happen).
     */
    UNDEFINED(0x00),
    /**
     * Key type for asymmetric key used for signing.
     */
    IDENTITY(0x10),
    /**
     * Key type for asymmetric keys used for key exchange (agreement).
     */
    EXCHANGE(0x20),
    /**
     * Key type for secret (symmetric) keys, used for encryption.
     */
    SECRET(0xE0),
    /**
     * Key type for shared (symmetric) keys, multipurpose.
     */
    SHARED(0xF0);

    KeyType(int value) {
        this.value = value;
    }

    public final int value;

    public static KeyType valueOf(int value) {

        switch (value) {
            case 0x00: return KeyType.UNDEFINED;
            case 0x10: return KeyType.IDENTITY;
            case 0x20: return KeyType.EXCHANGE;
            case 0xE0: return KeyType.SECRET;
            case 0xF0: return KeyType.SHARED;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }

}
