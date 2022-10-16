//
//  Tag.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.InvalidFormatException;
import java.util.List;
import java.util.UUID;

/**
 * A Dime item that uses item links to cryptographically connect itself to other items. This may be done to create
 * different types of proof, for example after verification, reception or handling.
 */
public class Tag extends Item {

    /// PUBLIC ///

    /** The item header for DiME Tag items.  */
    public static final String HEADER = "TAG";

    @Override
    public String getHeader() {
        return Tag.HEADER;
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
        setClaimValue(Claim.UID, UUID.randomUUID());
        setClaimValue(Claim.ISS, issuerId);
        setClaimValue(Claim.CTX, context);
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
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Tag.allowedClaims.contains(claim);
    }

    @Override
    protected String forExport() throws InvalidFormatException {
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

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.KID, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 3;


}
