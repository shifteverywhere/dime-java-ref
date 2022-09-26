//
//  Tag.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeFormatException;
import java.util.List;
import java.util.UUID;

/**
 * A Dime item that uses item links to cryptographically connect itself to other items. This may be done to create
 * different types of proof, for example after verification, reception or handling.
 */
public class Tag extends Item {

    /// PUBLIC ///

    /** The item type identifier forDime Tag items. */
    public static final String ITEM_IDENTIFIER = "TAG";

    @Override
    public String getItemIdentifier() {
        return Tag.ITEM_IDENTIFIER;
    }

    /**
     * Default constructor.
     * @param issuerId The issuer of the item.
     */
    public Tag(UUID issuerId) {
        this(issuerId, (String)null);
    }

    /**
     * Alternative constructor.
     * @param issuerId The issuer of the item.
     * @param context The context of the item.
     */
    public Tag(UUID issuerId, String context) {
        if (issuerId == null) { throw new IllegalArgumentException("Issuer identifier must not be null."); }
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        ClaimsMap claims = getClaims();
        claims.put(Claim.UID, UUID.randomUUID());
        claims.put(Claim.ISS, issuerId);
        claims.put(Claim.CTX, context);
    }

    /**
     * Alternative constructor.
     * @param issuerId The issuer of the item.
     * @param items List of items that should be linked.
     */
    public Tag(UUID issuerId, List<Item> items) {
        this(issuerId, null, items);
    }

    /**
     * Alternative constructor.
     * @param issuerId The issuer of the item.
     * @param context The context of the item.
     * @param items List of items that should be linked.
     */
    public Tag(UUID issuerId, String context, List<Item> items)  {
        this(issuerId, context);
        if (items != null) {
            setItemLinks(items);
        }
    }

    /// PACKAGE-PRIVATE ///

    Tag() { }

    /// PROTECTED ///

    @Override
    protected String forExport() throws DimeFormatException {
        if (this.itemLinks == null || this.itemLinks.isEmpty()) { throw new IllegalStateException("Unable to export tag, must contain at least 1 linked item."); }
        if (!isSigned()) { throw new IllegalStateException("Unable to export tag, must be signed first."); }
        return super.forExport();
    }

    @Override
    protected void customDecoding(List<String> components) {
        this.isSigned = true; // Tags are always signed
    }

    @Override
    protected int getMinNbrOfComponents() {
        return Tag.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final int MINIMUM_NBR_COMPONENTS = 3;


}
