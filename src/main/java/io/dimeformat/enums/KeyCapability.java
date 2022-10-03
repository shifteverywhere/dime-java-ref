//
//  Capability.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Defines different capabilities for cryptographic keys.
 */
public enum KeyCapability {

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
    ENCRYPT,
    /**
     * Similar to SIGN, however more used for cases where the key may be used in simpler integrity protection (MAC).
     */
    AUTHENTICATE;

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }

    /**
     * Create an KeyCapability from a string representation.
     * @param capability The string representation to convert from.
     * @return An KeyCapability instance.
     */
    public static KeyCapability fromString(String capability) {
        return KeyCapability.valueOf(capability.toLowerCase());
    }

    /**
     * Converts a legacy key type string to a KeyCapability.
     * @param legacy The legacy string to convert.
     * @return A KeyCapability instance.
     */
    public static KeyCapability keyCapabilityFromLegacy(String legacy) {
        switch (legacy.toLowerCase()) {
            case "identity": return KeyCapability.SIGN;
            case "exchange": return KeyCapability.EXCHANGE;
            case "encryption": return KeyCapability.ENCRYPT;
            case "authentication": return KeyCapability.AUTHENTICATE;
            default: return KeyCapability.UNDEFINED;
        }
    }

    /**
     * Converts a KeyCapability to a legacy key type string.
     * @param capability The capability to convert.
     * @return A legacy key type string.
     */
    public static String legacyFromKeyCapability(KeyCapability capability) {
        switch (capability) {
            case SIGN: return "identity";
            case EXCHANGE: return "exchange";
            case ENCRYPT: return "encryption";
            case AUTHENTICATE: return "authentication";
            default: return "undefined";
        }
    }

}
