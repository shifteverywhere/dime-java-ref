//
//  KeyVariant.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Defines rhe variant of a key, may either be SECRET or PUBLIC.
 * Used for header information in keys.
 */
public enum KeyVariant {

    /**
     * Secret keying material. If a key is marked with SECRET, then it should never
     * be stored or transmitted as plain text.
     */
    SECRET(0x00),
    /**
     * Public keying material. Keys marked as PUBLIC can safely be distributed and
     * shared with other parties.
     */
    PUBLIC(0x01);

    KeyVariant(int value) {
        this.value = (byte)value;
    }

    public final byte value;

    /**
     * Create from a byte value. Will throw IllegalStateException if an 
     * invalid value is provided.
     * @param value Byte value to use.
     * @return Enum instance.
     */
    public static KeyVariant valueOf(byte value) {
        switch (value) {
            case 0x00: return KeyVariant.SECRET;
            case 0x01: return KeyVariant.PUBLIC;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }

}
