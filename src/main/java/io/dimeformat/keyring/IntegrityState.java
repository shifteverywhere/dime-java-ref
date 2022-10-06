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
     *
     */
    VALID_DATES,
    /**
     *
     */
    VALID_ITEM_LINKS,
    /**
     * Signature is missing from the item being verified.
     */
    ERR_NO_SIGNATURE,
    /**
     * The item could not be verified to be trusted.
     */
    ERR_NOT_TRUSTED,
    /**
     * The key or keys used to verify the item does not match any signatures in that item.
     */
    ERR_KEY_MISMATCH,
    /**
     * The issuer id of the item does not match the subject id of the identity used for verification.
     */
    ERR_ISSUER_MISMATCH,
    /**
     * The item verified has passed its own expiration date and should not be used or trusted.
     */
    ERR_USED_AFTER_EXPIRED,
    /**
     * The item verified has not yet passed its issued at date and should not yet be used.
     */
    ERR_USED_BEFORE_ISSUED,
    /**
     * There is a mismatch in the expires at and issued at dates in the item. Item should not be used or trusted.
     */
    ERR_DATE_MISMATCH,
    /**
     * Any or all linked items could not be verified successfully. Full integrity of the item could not be verified,
     * should not be trusted.
     */
    ERR_LINKED_ITEM_FAULT,
    /**
     * There is a mismatch in item links and provided items.
     */
    ERR_LINKED_ITEM_MISMATCH,
    /**
     * No linked items found, so verification could not be completed.
     */
    ERR_LINKED_ITEM_MISSING,
    /**
     * An invalid item was encountered in the key ring, so verification could not be completed.
     */
    ERR_INVALID_KEY_RING_ITEM,
    /**
     * There are no keys or identities stored in the key rings, so verification could not be done.
     */
    ERR_NO_KEY_RING,
    /**
     * Verification encountered an unexpected internal error which could not be recovered from.
     */
    ERR_INTERNAL_FAULT;

    /**
     * Returns if the IntegrityState may be considered successfully validated and may be considered trusted.
     * @return True if valid, false otherwise.
     */
    public boolean isValid() {
        return this == COMPLETE || this == VALID_DATES || this == VALID_ITEM_LINKS;
    }

}
