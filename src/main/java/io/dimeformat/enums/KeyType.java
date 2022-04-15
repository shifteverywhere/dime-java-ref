//
//  KeyType.java
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
     * Key type for symmetric keys used for encryption.
     */
    ENCRYPTION(0xE0),
    /**
     * Key type for symmetric keys used for message authentication.
     */
    AUTHENTICATION(0xF0);

    KeyType(int value) {
        this.value = value;
    }

    /** The byte value of the enum. */
    public final int value;

    /**
     * Create from a byte value. Will throw IllegalStateException if an 
     * invalid value is provided.
     * @param value Byte value to use.
     * @return Enum instance.
     */
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
