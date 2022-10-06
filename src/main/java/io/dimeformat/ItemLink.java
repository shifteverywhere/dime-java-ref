//
//  ItemLink.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.exceptions.InvalidFormatException;
import io.dimeformat.keyring.IntegrityState;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Represents a link to a Dime item. This can be used to link Dime items together, which then would be signed and thus
 * create a cryptographic relationship.
 */
public final class ItemLink {

    /// PUBLIC ///

    /**
     * The item identifier, this is used to determine the Dime item type, i.e. "ID", "MSG", etc.
     */
    public final String itemIdentifier;
    /**
     * The thumbprint of the linked item. Used to determine if an item is the linked item.
     */
    public final String thumbprint;
    /**
     * The unique ID of the linked item.
     */
    public final UUID uniqueId;

    /**
     * Creates an item link from the provided Dime item.
     * @param item The Dime item to create the item link from.
     */
    public ItemLink(Item item) {
        if (item == null) { throw new IllegalArgumentException("Provided item must not be null."); }
        this.itemIdentifier = item.getItemIdentifier();
        try {
            this.thumbprint = item.thumbprint();
        } catch (CryptographyException e) {
            throw new IllegalArgumentException("Unable to create item link, exception caught: " + e);
        }
        this.uniqueId = item.getUniqueId();
    }

    /**
     * Creates an item link from the provided parameters.
     * @param itemIdentifier The Dime item identifier of the item, e.g. "ID", "MSG", etc.
     * @param thumbprint The thumbprint of the item to which the link should be created.
     * @param uniqueId The unique ID of the item to which the link should be created.
     */
    public ItemLink(String itemIdentifier, String thumbprint, UUID uniqueId) {
        if (itemIdentifier == null || itemIdentifier.isEmpty()) { throw new IllegalArgumentException("Provided item identifier must not be null or empty."); }
        if (thumbprint == null || thumbprint.isEmpty()) { throw new IllegalArgumentException("Provided thumbprint must not be null or empty."); }
        if (uniqueId == null) { throw new IllegalArgumentException("Provided unique ID must not be null."); }
        this.itemIdentifier = itemIdentifier;
        this.thumbprint = thumbprint;
        this.uniqueId = uniqueId;
    }

    /**
     * Returns an ItemLink instance from an encoded string.
     * @param encoded The encoded string.
     * @return Decoded ItemLink instance.
     * @throws InvalidFormatException If unable to decode the provided string.
     */
    public static ItemLink fromEncoded(String encoded) throws InvalidFormatException {
        if (encoded == null || encoded.isEmpty()) { throw new IllegalArgumentException("Encoded item link must not be null or empty."); }
        String[] components = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        if (components.length != 3) { throw new InvalidFormatException("Invalid item link format."); }
        return new ItemLink(components[0], components[2], UUID.fromString(components[1]));
    }

    /**
     * Returns a list of ItemLink instances from an encoded string.
     * @param encodedList The encoded string.
     * @return Decoded ItemLink instances in a list.
     * @throws InvalidFormatException If unable to decode the provided string.
     */
    public static List<ItemLink> fromEncodedList(String encodedList) throws InvalidFormatException {
        if (encodedList == null || encodedList.isEmpty()) { throw new IllegalArgumentException("Encoded list of item links must not be null or empty."); }
        String[] items = encodedList.split("\\" + Dime.SECTION_DELIMITER);
        ArrayList<ItemLink> links = new ArrayList<>();
        for (String item: items) {
            links.add(ItemLink.fromEncoded(item));
        }
        return links;
    }

    /**
     * Verifies if an item corresponds to the ItemLink.
     * @param item The item to verify against.
     * @return True if verified successfully.
     */
    public boolean verify(Item item) {
        if (item == null) { return false; }
        try {
            return uniqueId.equals(item.getUniqueId())
                    && itemIdentifier.equals(item.getItemIdentifier())
                    && thumbprint.equals(item.thumbprint());
        } catch (CryptographyException e) {
            return false;
        }
    }

    /**
     * Verifies a list of items towards a list of ItemLink instances.
     * @param items The items to verify against.
     * @param links The list of ItemLink instances.
     * @return The state of the integrity verification.
     */
    public static IntegrityState verify(List<Item> items, List<ItemLink> links) {
        if (items == null || links == null) {  return IntegrityState.ERR_LINKED_ITEM_MISSING; }
        for (Item item: items) {
            boolean matchFound = false;
            for (ItemLink link: links) {
                if (link.uniqueId.equals(item.getUniqueId())) {
                    matchFound = true;
                    try {
                        if (!link.itemIdentifier.equals(item.getItemIdentifier()) || !link.thumbprint.equals(item.thumbprint())) {
                            return IntegrityState.ERR_LINKED_ITEM_FAULT;
                        }
                    } catch (CryptographyException e) {
                        return IntegrityState.ERR_INTERNAL_FAULT;
                    }
                }
            }
            if (!matchFound) {
                return IntegrityState.ERR_LINKED_ITEM_MISMATCH;
            }
        }
        return IntegrityState.VALID_ITEM_LINKS;
    }

    /// PACKAGE-PRIVATE ///

    String toEncoded() {
        return this.itemIdentifier
                + Dime.COMPONENT_DELIMITER
                + this.uniqueId.toString()
                + Dime.COMPONENT_DELIMITER + this.thumbprint;
    }

    static String toEncoded(List<ItemLink> links) {
        if (links == null ||links.isEmpty()) { return null; }
        StringBuilder builder = new StringBuilder();
        for (ItemLink link: links) {
            if (builder.length() > 0) { builder.append(Dime.SECTION_DELIMITER); }
            builder.append(link.toEncoded());
        }
        return builder.toString();
    }

}
