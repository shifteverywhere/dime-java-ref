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
    UNDEFINED,
    /**
     * First generation cryptographic profile. Ed25519 for identity keys, X25519 for key exchange (agreement),
     * Blake2b-256 for hashes, and XYZ for encryption.
     */
    UNO

}
