//
//  ItemLink.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
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
     * The cryptographic suite used to generate the item link.
     */
    public String cryptoSuiteName;

    /**
     * Creates an item link from the provided DiME item.
     * @param item The DiME item to create the item link from.
     */
    public ItemLink(Item item) {
        this(item, null);
    }

    /**
     * Creates an item link from the provided DiME item.
     * @param item The DiME item to create the item link from.
     * @param cryptoSuiteName The name of the cryptographic suite to use, may be null.
     */
    public ItemLink(Item item, String cryptoSuiteName) {
        if (item == null) { throw new IllegalArgumentException("Provided item must not be null."); }
        this.itemIdentifier = item.getHeader();
        try {
            this.thumbprint = item.generateThumbprint(false);
        } catch (CryptographyException e) {
            throw new IllegalArgumentException("Unable to create item link, exception caught: " + e);
        }
        this.uniqueId = item.getClaim(Claim.UID);
        this.cryptoSuiteName = cryptoSuiteName != null ? cryptoSuiteName : Dime.crypto.getDefaultSuiteName();
    }

    /**
     * Creates an item link from the provided parameters.
     * @param itemIdentifier The Dime item identifier of the item, e.g. "ID", "MSG", etc.
     * @param thumbprint The thumbprint of the item to which the link should be created.
     * @param uniqueId The unique ID of the item to which the link should be created.
     * @param cryptoSuiteName The name of the cryptographic suite used.
     */
    public ItemLink(String itemIdentifier, String thumbprint, UUID uniqueId, String cryptoSuiteName) {
        if (itemIdentifier == null || itemIdentifier.isEmpty()) { throw new IllegalArgumentException("Provided item identifier must not be null or empty."); }
        if (thumbprint == null || thumbprint.isEmpty()) { throw new IllegalArgumentException("Provided thumbprint must not be null or empty."); }
        if (uniqueId == null) { throw new IllegalArgumentException("Provided unique ID must not be null."); }
        if (cryptoSuiteName == null ||cryptoSuiteName.isEmpty()) { throw new IllegalArgumentException("Provided cryptographic suite name must not be null."); }
        this.itemIdentifier = itemIdentifier;
        this.thumbprint = thumbprint;
        this.uniqueId = uniqueId;
        this.cryptoSuiteName = cryptoSuiteName;
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
        if (components.length < 3) { throw new InvalidFormatException("Invalid item link format."); }
        String suiteName = components.length == 4 ? components[3] : "STN";
        return new ItemLink(components[0], components[2], UUID.fromString(components[1]), suiteName);
    }

    /**
     * Returns a list of ItemLink instances from an encoded string.
     * @param encodedList The encoded string.
     * @return Decoded ItemLink instances in a list.
     * @throws InvalidFormatException If unable to decode the provided string.
     */
    public static List<ItemLink> fromEncodedList(String encodedList) throws InvalidFormatException {
        if (encodedList == null || encodedList.isEmpty()) { throw new IllegalArgumentException("Encoded list of item links must not be null or empty."); }
        String[] items = encodedList.split(Dime.SECTION_DELIMITER);
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
            return uniqueId.equals(item.getClaim(Claim.UID))
                    && itemIdentifier.equals(item.getHeader())
                    && thumbprint.equals(item.generateThumbprint(false, cryptoSuiteName));
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
        if (items == null || links == null) { throw new NullPointerException("Unable to verify linked items, provided lists must not be null."); }
        for (Item item: items) {
            boolean matchFound = false;
            for (ItemLink link: links) {
                if (link.uniqueId.equals(item.getClaim(Claim.UID))) {
                    matchFound = true;
                    try {
                        if (!link.itemIdentifier.equals(item.getHeader()) || !link.thumbprint.equals(item.generateThumbprint(false, link.cryptoSuiteName))) {
                            return IntegrityState.FAILED_LINKED_ITEM_FAULT;
                        }
                    } catch (CryptographyException e) {
                        return IntegrityState.FAILED_INTERNAL_FAULT;
                    }
                }
            }
            if (!matchFound) {
                return IntegrityState.FAILED_LINKED_ITEM_MISMATCH;
            }
        }
        return items.size() == links.size() ? IntegrityState.VALID_ITEM_LINKS : IntegrityState.PARTIALLY_VALID_ITEM_LINKS;
    }

    /// PACKAGE-PRIVATE ///

    String toEncoded() {
        StringBuilder builder = new StringBuilder();
        builder.append(this.itemIdentifier)
                .append( Dime.COMPONENT_DELIMITER)
                .append(this.uniqueId.toString())
                .append(Dime.COMPONENT_DELIMITER)
                .append(this.thumbprint);
        if (cryptoSuiteName != null && !cryptoSuiteName.equals("STN")) {
            builder.append(Dime.COMPONENT_DELIMITER)
                    .append(this.cryptoSuiteName);
        }
        return builder.toString();
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
