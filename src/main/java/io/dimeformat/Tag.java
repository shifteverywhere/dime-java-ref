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

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeFormatException;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class Tag extends Item {

    /// PUBLIC ///

    /** The item type identifier for Di:ME Tag items. */
    public static final String ITEM_IDENTIFIER = "TAG";

    @Override
    public String getItemIdentifier() {
        return Tag.ITEM_IDENTIFIER;
    }

    public Tag(UUID issuerId) {
        this(issuerId, null);
    }

    public Tag(UUID issuerId, String context) {
        if (issuerId == null) { throw new IllegalArgumentException("Issuer identifier must not be null."); }
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        getClaims().put(Claim.ISS, issuerId);
        getClaims().put(Claim.CTX, context);
    }

    public Tag(UUID issuerId, String context, List<Item> items) throws DimeCryptographicException {
        this(issuerId, context);
        if (items != null) {
            setItemLinks(items);
        }
    }

    /// PACKAGE-PRIVATE ///

    Tag() { }

    /// PROTECTED ///

    @Override
    protected String forExport() {
        if (this.itemLinks == null || this.itemLinks.isEmpty()) { throw new IllegalStateException("Unable to export tag, must contain at least 1 linked item."); }
        if (!isSigned()) { throw new IllegalStateException("Unable to export tag, must be signed first."); }
        return super.forExport();
    }

}
