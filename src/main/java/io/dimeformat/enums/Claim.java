//
//  Claim.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.enums;

/**
 * Standard claim names.
 */
public enum Claim {

    /**
     * Ambit - Describes the region, location or boundaries where the item is intended or valid (All).
     */
    AMB,
    /**
     * Audience ID - The identifier of the indented receiver, or audience, of the item (All).
     */
    AUD,
    /**
     * Capability - Describes the capabilities, or usages/constrains, of an item (Identity, Identity Issuing Request,
     * Key).
     */
    CAP,
    /**
     * Common Name - A common name, or alias, for the item, may be used to simplify manual identification of items (All).
     */
    CMN,
    /**
     * Context - The context for in which the item is to be used or valid (All).
     */
    CTX,
    /**
     * Expires at - The date and time when the item should be considered invalid and should no longer be used (All).
     */
    EXP,
    /**
     * Issued at - The date and time when the item should be considered valid and only used after (until expires at, if
     * specified) (All).
     */
    IAT,
    /**
     * Issuer ID - The identifier of the issuer of the item (All).
     */
    ISS,
    /**
     * Issuer URL - A URL or other form of resource locator where the issuer identity or public key may be fetched (All).
     */
    ISU,
    /**
     * Secret key - A secret key in raw format, may be a private key or a shared key (Key).
     */
    KEY,
    /**
     * Key ID - The identifier of a key that is related to the item (All).
     */
    KID,
    /**
     * Item links - Item links to other items that has been securely linked to the item (All).
     */
    LNK,
    /**
     * MIME type - The MIME type of any payload that is attached to the item (Data, Message).
     */
    MIM,
    /**
     * Method - Intended for use with external systems and data formats. Will be specified further in the future (All).
     */
    MTD,
    /**
     * Public key - A public key in raw format (Identity, Identity Issuing Request, Key, Message).
     */
    PUB,
    /**
     * Principle information - A key-value object with further information related to the principle related to the item
     * (Identity, Identity Issuing Request).
     */
    PRI,
    /**
     * Subject ID - The identifier of the subject related to the item (All).
     */
    SUB,
    /**
     * System name - The name of the system where the item originated from or belongs to (All).
     */
    SYS,
    /**
     * Unique ID - A unique identifier for the item (All).
     */
    UID;

    @Override
    public String toString() {
        return super.toString().toLowerCase();
    }

}
