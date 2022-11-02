//
//  Envelope.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import io.dimeformat.keyring.IntegrityState;
import java.io.IOException;
import java.util.*;

/**
 * An encapsulating object that can carry one or more Di:ME items. This is usually the format
 * that is exported and stored or transmitted. It will start with the header 'Di'.
 * Envelopes may be either anonymous or signed. An anonymous envelope, most frequently used,
 * is not cryptographically sealed, although the items inside normally are. A signed envelope
 * can contain one or more items and is itself also signed, it also has a small number of claims
 * attached to it.
 */
public class Envelope extends Item {

    /// PUBLIC ///

    /**
     * The maximum length that the context claim may hold.
     * This is also used for the context claim in messages.
     * @deprecated Will be removed in the future, use {#{@link Dime#MAX_CONTEXT_LENGTH}} instead.
     * */
    @Deprecated
    public static final int MAX_CONTEXT_LENGTH = Dime.MAX_CONTEXT_LENGTH;

    /** The standard envelope header. */
    public static final String HEADER = "Di";

    @Override
    public String getHeader() {
        return Envelope.HEADER;
    }

    /**
     * Returns any attached Di:ME items. This will be an array of Item instances
     * and may be cast by looking at the tag of the item (getTag).
     * @return An array of Item instance
     */
    public List<Item> getItems() {
        return this.items != null ? Collections.unmodifiableList(this.items) : null;
    }

    /**
     * Indicates if the envelope is anonymous (true) or if it is signed (false).
     * @return true or false
     */
    public boolean isAnonymous() {
        return !hasClaims();
    }

    /**
     * Default constructor for an anonymous envelope.
     */
    public Envelope() { }

    /**
     * Constructor to create a signed envelope with the identifier of the issuer.
     * @param issuerId The identifier of the issuer, may not be null.
     */
    public Envelope(UUID issuerId) {
        this(issuerId, null);
    }

    /**
     * Constructor to create a signed envelope with the identifier of the issuer and
     * a custom context claim. The context may be any valid text.
     * @param issuerId The identifier of the issuer, may not be null.
     * @param context The context to attach to the envelope, may be null.
     */
    public Envelope(UUID issuerId, String context) {
        if (issuerId == null) { throw new IllegalArgumentException("Issuer id may not be null."); }
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        putClaim(Claim.ISS, issuerId);
        putClaim(Claim.IAT, Utility.createTimestamp());
        putClaim(Claim.CTX, context);
    }

    /**
     * Imports an envelope from a Di:ME encoded string. This will not verify the envelope,
     * this has to be done by calling verify separately.
     * @param encoded The encoded Di:ME envelope to import.
     * @return The imported Envelope instance.
     * @throws InvalidFormatException If the format of the encoded envelope is wrong.
     */
    public static Envelope importFromEncoded(String encoded) throws InvalidFormatException {
        if (!encoded.startsWith(Envelope.HEADER)) { throw new InvalidFormatException("Not a Dime envelope object, invalid header."); }
        String[] sections = encoded.split(Dime.SECTION_DELIMITER);
        // 0: ENVELOPE
        String[] array = sections[0].split("\\" + Dime.COMPONENT_DELIMITER);
        Envelope envelope = new Envelope();
        envelope.components = new ArrayList<>(Arrays.asList(array));
        ArrayList<Item> items = new ArrayList<>(sections.length);
        for (int index = 1; index < sections.length; index++) {
            Item item = Item.fromEncoded(sections[index]);
            if (item == null) {
                if (index == sections.length - 1) { // This is most likely a signature
                    envelope.isSigned = true;
                } else {
                    throw new InvalidFormatException("Unable to import envelope, encountered invalid items.");
                }
            } else {
                items.add(item);
            }
        }
        envelope.items = items;
        if (!envelope.isSigned()) {
            envelope.encoded = encoded;
        } else {
            envelope.components.add(sections[sections.length -1]);
            envelope.encoded = encoded.substring(0, encoded.lastIndexOf(Dime.SECTION_DELIMITER));
            if (envelope.getSignatures().get(0).isLegacy()) {
                envelope.markAsLegacy();
            }
        }
        return envelope;
    }

    /**
     * Adds a Di:ME item (of type Item or any subclass thereof) to the envelope. For signed envelopes, this needs to be
     * done before signing the envelope.
     * @param item The Di:ME item to add.
     */
    public void addItem(Item item) {
        if (isSigned()) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        if (item instanceof Envelope) { throw new IllegalArgumentException("Not allowed to add an envelope to another envelope."); }
        if (this.items == null) {
            this.items = new ArrayList<>();
        }
        this.items.add(item);
    }

    /**
     * Adds a list of Di:ME items (of type Item or any subclass thereof) to the envelope. For signed envelopes, this
     * needs to be done before signing the envelope.
     * @param items The Di:ME items to add.
     */
    public void setItems(List<Item> items) {
        if (isSigned()) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        this.items = new ArrayList<>(items);
    }

    /**
     * Returns any item inside the envelope that matches the provided context (ctx).
     * @param context The context to look for.
     * @return The found item, or null if none was found.
     */
    public Item getItem(String context) {
        if (context == null || items == null || items.size() == 0) return null;
        for (Item item : items) {
            String ctx = item.getClaim(Claim.CTX);
            if (ctx != null && ctx.equalsIgnoreCase(context)) {
                return item;
            }
        }
        return null;
    }

    /**
     * Returns any item inside the envelope that matches the provided unique id (uid).
     * @param uniqueId The unique id to look for.
     * @return The found item, or null if none was found.
     */
    public Item getItem(UUID uniqueId) {
        if (uniqueId == null || items == null || items.size() == 0) return null;
        for (Item item : items) {
            if (item.getClaim(Claim.UID).equals(uniqueId)) {
                return item;
            }
        }
        return null;
    }

    /**
     * Signs the envelope using the provided key. The key must be of type IDENTITY. It is not possible to sign an
     * anonymous envelope. It is also not possible to sign an envelope if it already has been signed or does not
     * contain any Di:ME items.
     * @param key The key to use when signing.
     * @throws CryptographyException If something goes wrong.
     */
    @Override
    public void sign(Key key) throws CryptographyException {
        if (isLegacy()) {
            if (isAnonymous()) { throw new IllegalStateException("Unable to sign, envelope is anonymous."); }
            if (isSigned()) { throw new IllegalStateException("Unable to sign, envelope is already signed."); }
        }
        if (this.items == null || this.items.isEmpty()) { throw new IllegalStateException("Unable to sign, at least one item must be attached before signing an envelope."); }
        super.sign(key);
    }

    @Override
    public IntegrityState verify(Key verifyKey, List<Item> linkedItems)  {
        if (isLegacy()) {
            if (this.isAnonymous()) { throw new IllegalStateException("Unable to verify, envelope is anonymous."); }
        }
        return super.verify(verifyKey, linkedItems);
    }

    /**
     * Exports the envelope to a Di:ME encoded string.
     * @return The Di:ME encoded representation of the envelope.
     */
    @Override
    public String exportToEncoded() {
        if (!isAnonymous() && !isSigned()) { throw new IllegalStateException("Unable to export, envelope is not signed."); }
        try {
            return encoded(isSigned());
        } catch (InvalidFormatException e) {
            return null;
        }
    }

    /**
     * Returns the thumbprint of the envelope. This may be used to easily identify an envelope or detect if an
     * envelope has been changed. This is created by securely hashing the envelope and will be unique and change as
     * soon as any content changes.
     * @return The hash of the envelope as a hex string.
     * @throws CryptographyException If something goes wrong.
     */
    @Override
    public String generateThumbprint() throws CryptographyException {
        try {
            return Envelope.thumbprint(encoded(!isAnonymous()));
        } catch (InvalidFormatException e) {
            throw new CryptographyException("Unable to generate thumbprint for item, data invalid.");
        }
    }

    /// PROTECTED ///

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Envelope.allowedClaims.contains(claim);
    }

    @Override
    protected String encoded(boolean withSignature) throws InvalidFormatException {
        if (this.encoded == null) {
            StringBuilder builder = new StringBuilder();
            builder.append(Envelope.HEADER);
            if (!this.isAnonymous()) {
                builder.append(Dime.COMPONENT_DELIMITER);
                try {
                    builder.append(Utility.toBase64(exportClaims()));
                } catch (IOException e) {
                    throw new InvalidFormatException("Unexpected exception while encoding item: " + e);
                }
            }
            for (Item item : this.items) {
                builder.append(Dime.SECTION_DELIMITER);
                builder.append(item.forExport());
            }
            this.encoded = builder.toString();
        }
        if (withSignature && isSigned()) {
            return this.encoded + Dime.SECTION_DELIMITER + Signature.toEncoded(getSignatures());
        }
        return this.encoded;
    }

    @Override
    protected void customDecoding(List<String> components) {
        /* ignored */
    }

    /// PRIVATE ///

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.ISU, Claim.KID, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private ArrayList<Item> items;

}
