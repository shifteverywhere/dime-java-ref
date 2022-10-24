//
//  IntegrityState.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.keyring;

import io.dimeformat.Item;

/**
 * Holds the result from an item verification, i.e. using {@link Item#verify()} or related methods.
 */
public enum IntegrityState {

    /**
     * The integrity of the item was verified successfully, item can be trusted.
     */
    COMPLETE,
    /**
     * Signature validated is correct and item is intact (data integrity).
     */
    VALID_SIGNATURE,
    /**
     * Dates validated are correct and item within its validity period.
     */
    VALID_DATES,
    /**
     * Item links validated are correct.
     */
    VALID_ITEM_LINKS,
    /**
     * Signature is missing from the item being verified.
     */
    FAILED_NO_SIGNATURE,
    /**
     * The item could not be verified to be trusted.
     */
    FAILED_NOT_TRUSTED,
    /**
     * The key or keys used to verify the item does not match any signatures in that item.
     */
    FAILED_KEY_MISMATCH,
    /**
     * The issuer id of the item does not match the subject id of the identity used for verification.
     */
    FAILED_ISSUER_MISMATCH,
    /**
     * The item verified has passed its own expiration date and should not be used or trusted.
     */
    FAILED_USED_AFTER_EXPIRED,
    /**
     * The item verified has not yet passed its issued at date and should not yet be used.
     */
    FAILED_USED_BEFORE_ISSUED,
    /**
     * There is a mismatch in the expires at and issued at dates in the item. Item should not be used or trusted.
     */
    FAILED_DATE_MISMATCH,
    /**
     * Any or all linked items could not be verified successfully. Full integrity of the item could not be verified,
     * should not be trusted.
     */
    FAILED_LINKED_ITEM_FAULT,
    /**
     * There is a mismatch in item links and provided items.
     */
    FAILED_LINKED_ITEM_MISMATCH,
    /**
     * No linked items found, so verification could not be completed.
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
        return this == COMPLETE || this == VALID_SIGNATURE || this == VALID_DATES || this == VALID_ITEM_LINKS;
    }

}
