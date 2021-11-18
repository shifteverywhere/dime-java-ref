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
    ENCRYPTION(0xE0),
    AUTHENTICATION(0xF0);

    KeyType(int value) {
        this.value = value;
    }

    public final int value;

    public static KeyType valueOf(int value) {
        switch (value) {
            case 0x00: return KeyType.UNDEFINED;
            case 0x10: return KeyType.IDENTITY;
            case 0x20: return KeyType.EXCHANGE;
            case 0xE0: return KeyType.ENCRYPTION;
            case 0xF0: return KeyType.AUTHENTICATION;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }

}

enum AlgorithmFamily {

    UNDEFINED(0x00),
    AEAD(0x10),
    ECDH(0x40),
    EDDSA(0x80),
    HASH(0xE0);

    AlgorithmFamily(int value) {
        this.value = (byte)value;
    }

    public final byte value;

    public static AlgorithmFamily valueOf(byte value) {
        switch (value) {
            case 0x00: return AlgorithmFamily.UNDEFINED;
            case 0x10: return AlgorithmFamily.AEAD;
            case 0x40: return AlgorithmFamily.ECDH;
            case (byte)0x80: return AlgorithmFamily.EDDSA;
            case (byte)0xE0: return AlgorithmFamily.HASH;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }
}
