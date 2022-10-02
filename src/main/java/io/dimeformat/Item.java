//
//  Item.java
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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Base class for any other type of Di:ME items that can be included inside an Envelope instance. */
public abstract class Item {

    /// PUBLIC ///

    /**
     * Returns the type identifier of the Di:ME item. This can be used to identify the type of Di:ME object held in this
     * generic class. It is also used in the exported Di:ME format to indicate the beginning of a Di:ME item inside an
     * envelope. Typically, this is represented by a short series of letters.
     * @return The item type of the Di:ME item.
     */
    public abstract String getItemIdentifier();

    /**
     * Returns a unique identifier for the instance. This will be generated at item creation.
     * @return A unique identifier, as a UUID.
     */
    public UUID getUniqueId() {
        return getClaim(Claim.UID);
    }

    /**
     * Returns the identifier of the entity that created the Di:ME item (issuer). This may be optional depending on the
     * Di:ME item type.
     * @return The identifier of the issuer of the key.
     */
    public UUID getIssuerId() {
        return getClaim(Claim.ISS);
    }

    /**
     * The date and time when this Di:ME item was issued. Although, this date will most often be in the past, the
     * item should not be processed if it is in the future.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return getClaim(Claim.IAT);
    }

    /**
     * The date and time when the Di:ME item will expire, and should not be used and not trusted anymore after this
     * date.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getExpiresAt() {
        return getClaim(Claim.EXP);
    }

    /**
     * Returns the context that is attached to the Di:ME item.
     * @return A String instance.
     */
    public String getContext() {
        return getClaim(Claim.CTX);
    }

    /**
     * Checks if the item has been signed or not.
     * @return true or false.
     */
    public boolean isSigned() {
        return this.isSigned;
    }


    /**
     * Gets an item claim. Will throw IllegalArgumentException if claim requested is not support by the item type.
     * @param claim The claim to get the value for.
     * @return The claim value.
     * @param <T> Using generics.
     */
    public <T> T getClaim(Claim claim) {
        return getClaimMap().get(claim);
    }

    /**
     * Puts a value to an item claim. Will throw IllegalStateException is the item is already signed.
     * @param claim The claim to put a value to.
     * @param value The claim value.
     */
    public void putClaim(Claim claim, Object value) {
        throwIfSigned();
        if (!validClaim(claim)) { throw new IllegalArgumentException("Unsupported claim: " + claim); }
        getClaimMap().put(claim, value);
    }

    /**
     * Will remove the value from an item claim.
     * @param claim The claim to remove the value from.
     */
    public void removeClaim(Claim claim) {
        throwIfSigned();
        getClaimMap().remove(claim);
    }

    /**
     * Will import an item from a DiME encoded string. Di:ME envelopes cannot be imported using this method, for
     * envelopes use Envelope.importFromEncoded(String) instead.
     * @param encoded The Di:ME encoded string to import an item from.
     * @param <T> The subclass of item of the imported Di:ME item.
     * @return The imported Di:ME item.
     * @throws DimeFormatException If the encoded string is of a Di:ME envelope.
     */
    @SuppressWarnings("unchecked")
    public static <T extends Item> T importFromEncoded(String encoded) throws DimeFormatException {
        try {
            Envelope envelope = Envelope.importFromEncoded(encoded);
            List<Item> items = envelope.getItems();
            if (items.size() > 1) { throw new DimeFormatException("Multiple items found, import as 'Envelope' instead. (I1001)"); }
            return (T)items.get(0);
        } catch (ClassCastException e) {
            return null; // This is unlikely to happen
        }
    }

    /**
     * Exports the item to a Di:ME encoded string.
     * @return The Di:ME encoded representation of the item.
     */
    public String exportToEncoded() {
        Envelope envelope = new Envelope();
        if (isLegacy()) {
            envelope.convertToLegacy();
        }
        envelope.addItem(this);
        return envelope.exportToEncoded();
    }

    /**
     * Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
     * @param key The key to sign the item with, must be of type IDENTITY.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public void sign(Key key) throws DimeCryptographicException {
        if (isLegacy() && isSigned()) { throw new IllegalStateException("Unable to sign, legacy item is already signed."); }
        if (key == null || key.getSecret() == null) { throw new IllegalArgumentException("Unable to sign, key for signing must not be null. (I1004)"); }
        if (isSigned() && Signature.find(Dime.crypto.generateKeyName(key), getSignatures()) != null) { throw new IllegalStateException("Item already signed with provided key."); }
        try {
            byte[] signature = Dime.crypto.generateSignature(encoded(false), key);
            String name = isLegacy() ? null : Dime.crypto.generateKeyName(key);
            getSignatures().add(new Signature(signature, name));
            this.isSigned = true;
        } catch (DimeFormatException e) {
            throw new DimeCryptographicException("Unable to sign item, invalid data.");
        }
    }

    /**
     * Will remove all signatures from an item.
     * @return True if the item was stripped of signatures, false otherwise.
     */
    public boolean strip() {
        this.encoded = null;
        this.components = null;
        this._signatures = null;
        this.isSigned = false;
        return true;
    }

    /**
     * Will remove the signature created by the provided key, if one can be found.
     * @param key The key that created the signature to be removed.
     * @return True if the item was stripped of a signature, false otherwise.
     */
    public boolean strip(Key key) {
        if (!isLegacy() && isSigned()) {
           String identifier = Dime.crypto.generateKeyName(key);
            Signature signature = Signature.find(identifier, getSignatures());
            if (signature != null) {
                return getSignatures().remove(signature);
            }
        }
        return false;
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public String thumbprint() throws DimeCryptographicException {
        try {
            return Item.thumbprint(encoded(true));
        } catch (DimeFormatException e) {
            throw new DimeCryptographicException("Unable to generate thumbprint for item, data invalid.");
        }
    }

    /**
     * Returns the thumbprint of a DiME encoded item string. This may be used to easily identify an item or detect if
     * an item has been changed. This is created by securely hashing the item and will be unique and change as soon as
     * any content changes. This will generate the same value as the instance method thumbprint for the same (and
     * unchanged) item.
     * @param encoded The DiME encoded item string.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static String thumbprint(String encoded) throws DimeCryptographicException {
        return Item.thumbprint(encoded, Dime.crypto.getDefaultSuiteName());
    }

    /**
     *  Returns the thumbprint of a DiME encoded item string. This may be used to easily identify an item or detect if
     *  an item has been changed. This is created by securely hashing the item and will be unique and change as soon as
     *  any content changes. This will generate the same value as the instance method thumbprint for the same (and
     *  unchanged) item. If no cryptographic suite name is provided, then the suite set as default will be used.
     * @param encoded The DiME encoded item string.
     * @param suiteName The name of the cryptographic suite to use, may be null.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static String thumbprint(String encoded, String suiteName) throws DimeCryptographicException {
        return Utility.toHex(Dime.crypto.generateHash(encoded.getBytes(StandardCharsets.UTF_8), suiteName));
    }

    public void verify() throws VerificationException {
        verify((List<Item>) null);
    }

    public void verify(List<Item> linkedItems) throws VerificationException {
        if (!isSigned()) { throw new VerificationException(VerificationException.Reason.NO_SIGNATURE, this, "Unable to verify, item has no signatures."); }
        if (Dime.keyRing.size() == 0) { throw new VerificationException(VerificationException.Reason.NO_KEY_RING, this, "Unable to verify, no items found in key ring."); }
        for (Item item: Dime.keyRing.items()) {
            Key trustedKey;
            if (item instanceof Identity) {
                trustedKey = ((Identity) item).getPublicKey();
            } else if (item instanceof Key) {
                trustedKey = (Key) item;
            } else {
                throw new VerificationException(VerificationException.Reason.INVALID_ITEM, item, "Unable to verify, found invalid item in key ring.");
            }
            try {
                verify(trustedKey, linkedItems);
                return; // Return on first verified success
            } catch (VerificationException e) {
                if (e.reason != VerificationException.Reason.KEY_MISMATCH || isLegacy()) {
                    // No need to rethrow if a key could not find a matching signature (unless this is legacy).
                    throw e;
                }
            }

        }
        throw new VerificationException(VerificationException.Reason.NOT_TRUSTED, this, "Unable to verify, item not trusted.");
    }

    public void verify(Key trustedKey) throws VerificationException {
        verify(trustedKey, null);
    }

    public void verify(Key trustedKey, List<Item> linkedItems) throws VerificationException {
        if (trustedKey == null) { throw new IllegalArgumentException("Unable to verify, key must not be null."); }
        if (!isSigned()) { throw new VerificationException(VerificationException.Reason.NO_SIGNATURE, this, "Unable to verify, item has no signatures."); }
        Signature signature;
        if (isLegacy()) {
            signature = getSignatures().get(0);
        } else {
            signature = Signature.find(Dime.crypto.generateKeyName(trustedKey), getSignatures());
        }
        if (signature == null) {
            throw new VerificationException(VerificationException.Reason.KEY_MISMATCH, this,  "Unable to verify, no matching signature found for key.");
        } else {
            try {
                if (!Dime.crypto.verifySignature(encoded(false), signature.bytes, trustedKey)) {
                    throw new VerificationException(VerificationException.Reason.NOT_TRUSTED, this, "Unable to verify, item is not trusted.");
                }
            } catch (DimeFormatException | DimeCryptographicException e) {
                throw new VerificationException(VerificationException.Reason.INTERNAL_ERROR, this, "Unable to verify, encountered an unexpected internal fault.", e);
            }
        }
        Item.verifyDates(this); // This throws VerificationException if unable to verify
        if (linkedItems != null && !linkedItems.isEmpty()) {
            verifyLinkedItems(linkedItems); // This throws VerificationException if unable to verify
        }
    }

    public void verify(Identity issuer) throws VerificationException {
        verify(issuer, null);
    }

     /**
     * Verifies the signature of the item using the key from the provided issuer identity. Will also verify that the
     * claim issuer (iss) matches the subject id (sub) of the provided identity. Any items provided in linkedItems will
     * be verified with item links in the Dime item, if they cannot be verified correctly, then DimeIntegrityException
     * will be thrown. Only items provided will be verified, any additional item links will be ignored. Providing items
     * that are not linked will also result in a DimeIntegrityException being thrown.
     * @param issuer The issuer identity to use while verifying.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @throws VerificationException If item could not be verified.
     */
    public void verify(Identity issuer, List<Item> linkedItems) throws VerificationException {
        if (issuer == null) { throw new IllegalArgumentException("Unable to verify, issuer must not be null."); }
        UUID issuerId = getClaim(Claim.ISS);
        if (issuerId != null && !issuerId.equals(issuer.getSubjectId())) { throw new VerificationException(VerificationException.Reason.ISSUER_MISMATCH, this, "Unable to verify, subject id of provided issuer identity do not match item issuer id, expected: " + issuerId + ", got: " + issuer.getSubjectId()); }
        verify(issuer.getPublicKey(), linkedItems);
    }

    /**
     * Will cryptographically link an item link from provided item to this item.
     * @param item The item to link to the tag.
     */
    public void addItemLink(Item item) {
        throwIfSigned();
        if (item == null) { throw new IllegalArgumentException("Item to link with must not be null."); }
        if (this.itemLinks == null) {
            this.itemLinks = new ArrayList<>();
        }
        this.itemLinks.add(new ItemLink(item));
    }

    /**
     * Will cryptographically link item links of provided items to this item.
     * @param items The items to link.
     */
    public void setItemLinks(List<Item> items) {
        throwIfSigned();
        if (items == null) { throw new IllegalArgumentException("Items to link with must not be null."); }
        this.itemLinks = new ArrayList<>();
        for (Item item: items) {
            this.itemLinks.add(new ItemLink(item));
        }
    }

    /**
     * Returns a list of item links.
     * @return A list of ItemLink instances, null if there are no links.
     */
    public List<ItemLink> getItemLinks() {
        if (this.itemLinks == null) {
            this.itemLinks = getClaim(Claim.LNK);
        }
        return this.itemLinks;
    }

    /**
     * Removes all item links.
     */
    public void removeLinkItems() {
        if (getClaimMap().get(Claim.LNK) == null) return;
        throwIfSigned();
        getClaimMap().remove(Claim.LNK);
        this.itemLinks = null;
    }

    /**
     * Converts the item to legacy (before official Dime version 1).
     */
    public void convertToLegacy() {
        strip();
        legacy = true;
    }

    /**
     * Checks if the item is legacy (before official Dime version 1).
     * @return True if legacy, false is not.
     */
    public boolean isLegacy() { return this.legacy; }

    /// PACKAGE-PRIVATE ///

    static final int MINIMUM_NBR_COMPONENTS = 2;
    static final int COMPONENTS_IDENTIFIER_INDEX = 0;
    static final int COMPONENTS_CLAIMS_INDEX = 1;

    void markAsLegacy() {
        legacy = true;
    }

    @SuppressWarnings("unchecked")
    static <T extends Item> T fromEncoded(String encoded) throws DimeFormatException {
        try {
            var t = Item.classFromTag(encoded.substring(0, encoded.indexOf(Dime.COMPONENT_DELIMITER)));
            T item;
            try {
                item = (T) Objects.requireNonNull(t).getDeclaredConstructor().newInstance();
            } catch (Exception e) {
                throw new DimeFormatException("Unexpected exception (I1002).", e);
            }
            item.decode(encoded);
            return item;
        } catch (ClassCastException e) {
            return null; // This is unlikely to happen
        }
    }

    String forExport() throws DimeFormatException {
        return encoded(true);
    }

    /// PROTECTED ///

    protected String encoded;
    protected List<String> components;
    protected List<ItemLink> itemLinks;
    protected boolean isSigned = false;

    protected abstract boolean validClaim(Claim claim);

    protected String exportClaims() throws IOException{
        return getClaimMap().toJSON();
    }

    protected final boolean hasClaims() {
        if (this._claims == null && this.components != null) {
            return this.components.size() >= Item.MINIMUM_NBR_COMPONENTS;
        }
        return this._claims != null && this._claims.size() > 0;
    }

    protected final List<Signature> getSignatures() {
        if (this._signatures == null) {
            if (isSigned()) {
                this._signatures = Signature.fromEncoded(this.components.get(this.components.size() - 1));
            } else {
               this._signatures = new ArrayList<>();
            }
        }
        return this._signatures;
    }

    protected static void verifyDates(Item item) throws VerificationException {
        Instant now = Utility.createTimestamp();
        if (Utility.gracefulTimestampCompare(item.getIssuedAt(), now) > 0) { throw new VerificationException(VerificationException.Reason.USE_BEFORE, item, "Unable to verify, issued at date in the future."); }
        if (item.getExpiresAt() != null) {
            if (Utility.gracefulTimestampCompare(item.getIssuedAt(), item.getExpiresAt()) > 0) { throw new VerificationException(VerificationException.Reason.DATE_MISMATCH, item, "Unable to verify, expires at before issued at date."); }
            if (Utility.gracefulTimestampCompare(item.getExpiresAt(), now) < 0) { throw new VerificationException(VerificationException.Reason.USE_AFTER, item, "Unable to verify, passed expires at date."); }
        }
    }

    protected void verifyLinkedItems(List<Item> linkedItems) throws VerificationException {
        if (itemLinks == null) {
            itemLinks = getClaim(Claim.LNK);
        }
        if (itemLinks != null) {
            ItemLink.verify(linkedItems, itemLinks);
        } else {
            throw new VerificationException(VerificationException.Reason.LINKED_ITEM_FAULT, this, "Unable to verify, no linked items found.");
        }
    }

    /// --- ENCODING/DECODING --- ///

    protected String encoded(boolean withSignature) throws DimeFormatException {
        if (this.encoded == null) {
            StringBuilder builder = new StringBuilder();
            customEncoding(builder);
            this.encoded = builder.toString();
        }
        if (withSignature && isSigned()) {
            return this.encoded + Dime.COMPONENT_DELIMITER + Signature.toEncoded(getSignatures());
        }
        return this.encoded;
    }

    protected void customEncoding(StringBuilder builder) throws DimeFormatException {
        builder.append(this.getItemIdentifier());
        builder.append(Dime.COMPONENT_DELIMITER);
        if (itemLinks != null && !itemLinks.isEmpty()) {
            getClaimMap().put(Claim.LNK, ItemLink.toEncoded(itemLinks));
        }
        try {
            builder.append(Utility.toBase64(this._claims.toJSON()));
        } catch (IOException e) {
            throw new DimeFormatException("Unexpected exception while encoding item: " + e);
        }

    }

    protected final void decode(String encoded) throws DimeFormatException {
        String[] array = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        if (array.length < getMinNbrOfComponents()) { throw new DimeFormatException("Unexpected number of components for Dime item, expected at least " + getMinNbrOfComponents() + ", got " + array.length +"."); }
        if (array[Item.COMPONENTS_IDENTIFIER_INDEX].compareTo(getItemIdentifier()) != 0) { throw new DimeFormatException("Unexpected Dime item identifier, expected: " + getItemIdentifier() + ", got " + array[Item.COMPONENTS_IDENTIFIER_INDEX] + "."); }
        this.components = new ArrayList<>(Arrays.asList(array));
        customDecoding(this.components);
        if (isSigned()) {
            if (getSignatures().get(0).isLegacy()) {
                markAsLegacy();
            }
            this.encoded = encoded.substring(0, encoded.lastIndexOf(Dime.COMPONENT_DELIMITER));
        } else {
            this.encoded = encoded;
        }
    }

    protected abstract void customDecoding(List<String> components) throws DimeFormatException;

    protected int getMinNbrOfComponents() {
        return Item.MINIMUM_NBR_COMPONENTS;
    }

    protected final void throwIfSigned() {
        if (isSigned()) {
            throw new IllegalStateException("Unable to complete operation, Di:ME item already signed.");
        }
    }

    /// PRIVATE ///

    private ClaimsMap _claims;
    private List<Signature> _signatures;
    private boolean legacy = false;

    private final ClaimsMap getClaimMap() {
        if (this._claims == null) {
            if (this.components != null && this.components.size() > Item.COMPONENTS_CLAIMS_INDEX) {
                byte[] jsonClaims = Utility.fromBase64(this.components.get(Item.COMPONENTS_CLAIMS_INDEX));
                this._claims = new ClaimsMap(new String(jsonClaims, StandardCharsets.UTF_8));
            } else {
                this._claims = new ClaimsMap();
            }
        }
        return this._claims;
    }

    private static Class<?> classFromTag(String tag) {
        switch (tag) {
            case Data.ITEM_IDENTIFIER: return Data.class;
            case Identity.ITEM_IDENTIFIER: return Identity.class;
            case IdentityIssuingRequest.ITEM_IDENTIFIER: return IdentityIssuingRequest.class;
            case Key.ITEM_IDENTIFIER: return Key.class;
            case Message.ITEM_IDENTIFIER: return Message.class;
            case Tag.ITEM_IDENTIFIER: return Tag.class;
            default: return null;
        }
    }

}
