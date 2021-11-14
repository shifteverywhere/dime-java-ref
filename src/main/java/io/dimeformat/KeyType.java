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
    UNDEFINED,
    /**
     * Key type for asymmetric key used for signing.
     */
    IDENTITY,
    /**
     * Key type for asymmetric keys used for key exchange (agreement).
     */
    EXCHANGE,
    /**
     * Key type for secret (symmetric) keys, used for encryption.
     */
    SECRET,
    /**
     * Key type for shared (symmetric) keys, multipurpose.
     */
    SHARED

}
