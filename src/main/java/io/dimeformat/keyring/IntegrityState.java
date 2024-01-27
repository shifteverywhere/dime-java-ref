//
//  IntegrityState.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.keyring;

import io.dimeformat.Item;

/**
 * Holds the result from an item verification, i.e. using {@link Item#verify()} or related methods.
 */
public enum IntegrityState {

    /**
     * All parts of the DiME item was successfully verified and the item may be trusted.
     */
    COMPLETE,
    /**
     * All parts of the DiME item was successfully verified. However, not all linked items where verified, although, those
     * that where was successful.
     */
    PARTIALLY_COMPLETE,
    /**
     * All verified parts of the DiME item was successful. However, some parts where skipped, like linked items as no
     * list of items where provided.
     */
    INTACT,
    /**
     * The signature of the DiME item was verified successfully. No other parts where verified.
     */
    VALID_SIGNATURE,
    /**
     * The dates (issued at and/or expires at) in the DiME item were verified successfully. No other parts where verified.
     */
    VALID_DATES,
    /**
     * Any linked items where verified successfully against a provided item list. No items where skipped or missing. No
     * other parts where verified.
     */
    VALID_ITEM_LINKS,
    /**
     * All linked items where verified successfully against a provided item list. Any list, linked items or provided
     * items, may contain items not in the other list. No other parts where verified.
     */
    PARTIALLY_VALID_ITEM_LINKS,
    /**
     * Unable to verify the digital signature, as the DiME item did not contain a signature.
     */
    FAILED_NO_SIGNATURE,
    /**
     * The digital signature could not be successfully verified, and, thus the DiME item must not be trusted.
     */
    FAILED_NOT_TRUSTED,
    /**
     * The public key used to verify the DiME item does not match the key pair used to generate the digital signature.
     */
    FAILED_KEY_MISMATCH,
    /**
     * The issuer ID ("iss") in the DiME identity used when verifying does not match issuer ID ("iss") set in the item
     * verified.
     */
    FAILED_ISSUER_MISMATCH,
    /**
     * The expiration date ("exp") set in the DiME item verified has passed, and the item should no longer be used.
     */
    FAILED_USED_AFTER_EXPIRED,
    /**
     * The issued at date ("iat") set in the DiME item has not yet passed, and the item should not be used yet.
     */
    FAILED_USED_BEFORE_ISSUED,
    /**
     * The dates set in the DiME item verified are incorrect, where the issued at date ("iat") is after the expiration
     * date ("exp").
     */
    FAILED_DATE_MISMATCH,
    /**
     * One, or several, linked items could not be verified successfully.
     */
    FAILED_LINKED_ITEM_FAULT,
    /**
     * Provided item list to verify linked items contains additional, non-linked, items.
     */
    FAILED_LINKED_ITEM_MISMATCH,
    /**
     * No linked items found when verifying with a provided item list.
     */
    FAILED_LINKED_ITEM_MISSING,
    /**
     * An invalid item was encountered in the key ring, so verification could not be completed.
     */
    FAILED_INVALID_KEY_RING_ITEM,
    /**
     * There are no keys or identities stored in the key rings, so verification could not be done.
     */
    FAILED_NO_KEY_RING,
    /**
     * Verification encountered an unexpected internal error which could not be recovered from.
     */
    FAILED_INTERNAL_FAULT;

    /**
     * Returns if the IntegrityState may be considered successfully validated and may be considered trusted.
     * @return True if valid, false otherwise.
     */
    public boolean isValid() {
        return this == COMPLETE
                || this == PARTIALLY_COMPLETE
                || this == INTACT
                || this == VALID_SIGNATURE
                || this == VALID_DATES
                || this == VALID_ITEM_LINKS
                || this == PARTIALLY_VALID_ITEM_LINKS;
    }

}
