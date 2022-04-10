//
//  AlgorithmFamily.java
//  Di:ME - Data Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Defines the family a particular algorithm belongs to.
 * Used for header information in keys.
 */
public enum AlgorithmFamily {

    /** 
     * Undefined algorithm.
    */
    UNDEFINED(0x00),
    /**
     * Symmetric authentication encryption algorithm.
     */
    AEAD(0x10),
    /**
     * Asymmetric Elliptic Curve key agreement algorithm.
     */
    ECDH(0x40),
    /**
     * Asymmetric Edwards-curve digital signature algorithm
     */
    EDDSA(0x80),
    /**
     * Secure hashing algorithm.
     */
    HASH(0xE0);

    AlgorithmFamily(int value) {
        this.value = (byte)value;
    }

    /** The byte value of the enum. */
    public final byte value;

    /**
     * Create from a byte value. Will throw IllegalStateException if an 
     * invalid value is provided.
     * @param value Byte value to use.
     * @return Enum instance.
     */
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

    /**
     * Creates from a key type.
     * @param type Key type to use.
     * @return Enum instance.
     */
    public static AlgorithmFamily keyTypeOf(KeyType type) {
        switch (type) {
            case ENCRYPTION: return AlgorithmFamily.AEAD;
            case EXCHANGE: return AlgorithmFamily.ECDH;
            case IDENTITY: return AlgorithmFamily.EDDSA;
            case AUTHENTICATION: return AlgorithmFamily.HASH;
            default: throw new IllegalStateException("Unexpected value: " + type);
        }
    }
    
}