//
//  Profile.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

public enum Profile {

    /**
     * Undefined profile, used when a profile wasn't set properly, for errors.
     */
    UNDEFINED(0x00),
    /**
     * First generation cryptographic profile. Ed25519 for identity keys, X25519 for key exchange (agreement),
     * Blake2b-256 for hashes, and XYZ for encryption.
     */
    UNO(0x01);

    Profile(int value) {
        this.value = value;
    }

    public int value;

    public static Profile valueOf(int value) {

        switch (value) {
            case 0x00: return Profile.UNDEFINED;
            case 0x01: return Profile.UNO;
            default: throw new IllegalStateException("Unexpected value: " + value);
        }
    }

}
