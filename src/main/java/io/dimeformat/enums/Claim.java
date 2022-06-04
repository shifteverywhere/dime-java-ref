//
//  Claim.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Default claim names.
 */
public enum Claim {

    /**
     * Ambit
     */
    AMB,
    /**
     * Audience
     */
    AUD,
    /**
     * Capability
     */
    CAP,
    /**
     * Context
     */
    CTX,
    /**
     * Expires at
     */
    EXP,
    /**
     * Issued at
     */
    IAT,
    /**
     * Issuer
     */
    ISS,
    /**
     * Key
     */
    KEY,
    /**
     * Key ID
     */
    KID,
    /**
     * Link
     */
    LNK,
    /**
     * MIME type
     */
    MIM,
    /**
     * Method
     */
    MTD,
    /**
     * Public key
     */
    PUB,
    /**
     * Principles
     */
    PRI,
    /**
     * Subject
     */
    SUB,
    /**
     * System
     */
    SYS,
    /**
     * Unique ID
     */
    UID,
    /**
     * Key usage
     */
    USE;

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }

}
