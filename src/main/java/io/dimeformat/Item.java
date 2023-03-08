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
import io.dimeformat.keyring.IntegrityState;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/** Base class for any other type of Di:ME items that can be included inside an Envelope instance. */
public abstract class Item {

    /// PUBLIC ///

    /**
     * Returns the item header of the DiME item. This can be used to identify the type of DiME item held in this
     * generic class. It is also used in the exported DiME format to indicate the beginning of a DiME item inside an
     * envelope. Typically, this is represented by a short series of letters.
     * @return The item header of the DiME item.
     */
    public abstract String getHeader();

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
        if (!allowedToSetClaimDirectly(claim)) { throw new IllegalArgumentException("Unable to set claim '" + claim + "', may be unsupported or locked."); }
        setClaimValue(claim, value);
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
     * Will import an item from a DiME encoded string. DiME envelopes cannot be imported using this method, for
     * envelopes use {@link Envelope#importFromEncoded(String)} instead.
     * @param encoded The DiME encoded string to import an item from.
     * @param <T> The subclass of item of the imported DiME item.
     * @return The imported Di:ME item.
     * @throws InvalidFormatException If the encoded string is of a DiME envelope.
     */
    @SuppressWarnings("unchecked")
    public static <T extends Item> T importFromEncoded(String encoded) throws InvalidFormatException {
        try {
            Envelope envelope = Envelope.importFromEncoded(encoded);
            List<Item> items = envelope.getItems();
            if (items.size() > 1) { throw new InvalidFormatException("Multiple items found, import as 'Envelope' instead. (I1001)"); }
            return (T)items.get(0);
        } catch (ClassCastException e) {
            return null; // This is unlikely to happen
        }
    }

    /**
     * Exports the item to a DiME encoded string.
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

    @Override
    public String toString() {
        return exportToEncoded();
    }

    /**
     * This will return the encoded item as a byte-array. This should only be used when needing a raw version of the
     * item for cryptographic operations. For distribution and storage {@link #exportToEncoded()} should be used.
     * @param withSignatures Indicates if returned byte-array should contain any attached signatures.
     * @return The item as a byte-array.
     */
    public byte[] rawEncoded(boolean withSignatures) {
        try {
            return encoded(withSignatures).getBytes(StandardCharsets.UTF_8);
        } catch (InvalidFormatException e) {
            return null;
        }
    }

    /**
     * Will check if an item is within a particular ambit.
     * @param ambit The ambit to check for.
     * @return true or false.
     */
    public boolean hasAmbit(String ambit) {
        List<String> ambitList = getClaim(Claim.AMB);
        if (ambitList != null) {
            return ambitList.contains(ambit);
        }
        return false;
    }

    /**
     * Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
     * @param signingKey The key to sign the item with, must be of type IDENTITY.
     * @throws CryptographyException If something goes wrong.
     */
    public void sign(Key signingKey) throws CryptographyException {
        if (isLegacy() && isSigned()) { throw new IllegalStateException("Unable to sign, legacy item is already signed."); }
        if (signingKey == null || signingKey.getSecret() == null) { throw new IllegalArgumentException("Unable to sign, key for signing must not be null. (I1004)"); }
        if (isSigned() && Signature.find(Dime.crypto.generateKeyName(signingKey), getSignatures()) != null) { throw new IllegalStateException("Item already signed with provided key."); }
        try {
            Signature signature = Dime.crypto.generateSignature(this, signingKey);
            getSignatures().add(signature);
            this.isSigned = true;
        } catch (Exception e) {
            throw new CryptographyException("Unable to sign item, invalid data.");
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
        if (isLegacy() || !isSigned()) { return false; }
       String identifier = Dime.crypto.generateKeyName(key);
        Signature signature = Signature.find(identifier, getSignatures());
        if (signature != null) {
            return getSignatures().remove(signature);
        }
        return false;
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes. Any signatures attached to the item will be included in the generation of the thumbprint. The encoded
     * format of the returned string is determined by the default cryptographic suite.
     * @return The hash (thumbprint) of the item as an encoded string.
     * @throws CryptographyException If something goes wrong.
     */
    public String generateThumbprint() throws CryptographyException {
        return generateThumbprint(true, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes. The encoded format of the returned string is determined by the default cryptographic suite.
     * @param includeSignatures If attached signatures should be included when generating the thumbprint.
     * @return The hash (thumbprint) of the item as an encoded string.
     * @throws CryptographyException If something goes wrong.
     */
    public String generateThumbprint(boolean includeSignatures) throws CryptographyException {
        return generateThumbprint(includeSignatures, Dime.crypto.getDefaultSuiteName());
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes. The encoded format of the returned string is determined by the cryptographic suite specified.
     * @param includeSignatures If attached signatures should be included when generating the thumbprint.
     * @param suiteName The name of the cryptographic suite to use, may be null.
     * @return The hash (thumbprint) of the item as an encoded string.
     * @throws CryptographyException If something goes wrong.
     */
    public String generateThumbprint(boolean includeSignatures, String suiteName) throws CryptographyException {
        try {
            return Item.thumbprint(encoded(includeSignatures), suiteName);
        } catch (InvalidFormatException e) {
            throw new CryptographyException("Unable to generate thumbprint for item, data invalid.");
        }
    }

    /**
     * Returns the thumbprint of a DiME encoded item string. This may be used to easily identify an item or detect if
     * an item has been changed. This is created by securely hashing the item and will be unique and change as soon as
     * any content changes. This will generate the same value as the instance method thumbprint for the same (and
     * unchanged) item. The encoded format of the returned string is determined by the default cryptographic suite.
     * @param encoded The DiME encoded item string.
     * @return The hash of the item as a hex string.
     * @throws CryptographyException If something goes wrong.
     */
    public static String thumbprint(String encoded) throws CryptographyException {
        return Item.thumbprint(encoded, Dime.crypto.getDefaultSuiteName());
    }

    /**
     *  Returns the thumbprint of a DiME encoded item string. This may be used to easily identify an item or detect if
     *  an item has been changed. This is created by securely hashing the item and will be unique and change as soon as
     *  any content changes. This will generate the same value as the instance method thumbprint for the same (and
     *  unchanged) item. If no cryptographic suite name is provided, then the suite set as default will be used.
     *  The encoded format of the returned string is determined by the cryptographic suite specified.
     * @param encoded The DiME encoded item string.
     * @param suiteName The name of the cryptographic suite to use, may be null.
     * @return The hash of the item as a hex string.
     * @throws CryptographyException If something goes wrong.
     */
    public static String thumbprint(String encoded, String suiteName) throws CryptographyException {
        return Dime.crypto.generateHash(encoded.getBytes(StandardCharsets.UTF_8), suiteName);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. The verification will be made using the public
     * key in the provided identity. The verification will also check if the item has been issued by the provided
     * identity, if the "iss" claim has been set.
     * @param issuingIdentity The issuing identity to use when verifying.
     * @return The integrity state of the verification.
     */
    public IntegrityState verify(Identity issuingIdentity) {
        return verify(issuingIdentity, null);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. The verification will be made using the public
     * key in the provided identity. The verification will also check if the item has been issued by the provided
     * identity, if the "iss" claim has been set.
     * @param trustedIdentity A trusted identity to verify with.
     * @param linkedItems A list of item where item links should be verified, may be null.
     * @return The integrity state of the verification.
     */
    public IntegrityState verify(Identity trustedIdentity, List<Item> linkedItems) {
        UUID issuerId = getClaim(Claim.ISS);
        if (issuerId != null && !issuerId.equals(trustedIdentity.getClaim(Claim.SUB))) {
            return IntegrityState.FAILED_ISSUER_MISMATCH;
        }
        IntegrityState state = trustedIdentity.verifyDates();
        if (!state.isValid()) {
            return state;
        }
        return verify(trustedIdentity.getPublicKey(), linkedItems);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. Keys used for verification will be fetched from
     * the local key ring.
     * @return The integrity state of the verification.
     */
    public IntegrityState verify() {
        return verify((Key) null, null);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. If a key is provided, then verification will
     * use that key. If verifyKey is omitted, then the local key ring will be used to verify signatures of the item.
     * @param verifyKey Key used to verify the item, may be null.
     * @return The integrity state of the verification.
     */
    public IntegrityState verify(Key verifyKey) {
        return verify(verifyKey, null);
    }

    /**
     * Verifies the integrity and over all validity and trust of the item. If a key is provided, then verification will
     * use that key. If verifyKey is omitted, then the local key ring will be used to verify signatures of the item.
     * @param verifyKey Key used to verify the item, may be null.
     * @param linkedItems A list of item where item links should be verified, may be null.
     * @return The integrity state of the verification.
     */
    public IntegrityState verify(Key verifyKey, List<Item> linkedItems) {
        IntegrityState state = verifyDates();
        if (!state.isValid()) {
            return state;
        }
        boolean partiallyIntact = false;
        if (linkedItems != null) {
            state = verifyLinkedItems(linkedItems);
            if (!state.isValid()) {
                return state;
            }
            partiallyIntact = state == IntegrityState.PARTIALLY_VALID_ITEM_LINKS;
        }
        state = verifySignature(verifyKey);
        return !state.isValid() ? state : partiallyIntact ? IntegrityState.INTACT :
                linkedItems == null && getClaim(Claim.LNK) != null ? IntegrityState.PARTIALLY_COMPLETE : IntegrityState.COMPLETE;
    }

    /**
     * Verifies any dates in the item. This will verify the validity period of the item, if it should be used or if it
     * has expired. Failure here does not necessary mean that the item cannot be trusted, the dates of item is no longer
     * valid, refer to the returned state.
     * @return The integrity state of the verification.
     */
    public IntegrityState verifyDates() {
        if (!hasClaims()) {
            return IntegrityState.VALID_DATES;
        }
        Instant now = Utility.createTimestamp();
        if (Utility.gracefulTimestampCompare(getClaim(Claim.IAT), now) > 0) { return IntegrityState.FAILED_USED_BEFORE_ISSUED; }
            if (getClaim(Claim.EXP) != null) {
                if (Utility.gracefulTimestampCompare(getClaim(Claim.IAT), getClaim(Claim.EXP)) > 0) { return IntegrityState.FAILED_DATE_MISMATCH; }
                if (Utility.gracefulTimestampCompare(getClaim(Claim.EXP), now) < 0) { return IntegrityState.FAILED_USED_AFTER_EXPIRED; }
            }
        return IntegrityState.VALID_DATES;
    }

    /**
     * Verifies signatures of the item. The method will try to match an associated signature of the item to the provided
     * key. If no key is provided, then the local key ring will be used to verify the item.
     * @param verifyKey The key to use for verification, may be null.
     * @return The integrity state of the verification.
     */
    public IntegrityState verifySignature(Key verifyKey) {
        if (!isSigned()) {
            return IntegrityState.FAILED_NO_SIGNATURE;
        }
        if (verifyKey == null) {
            return Dime.keyRing.verify(this);
        }
        Signature signature = isLegacy() ? getSignatures().get(0) : Signature.find(Dime.crypto.generateKeyName(verifyKey), getSignatures());
        if (signature == null) {
            return IntegrityState.FAILED_KEY_MISMATCH;
        }
        try {
            return Dime.crypto.verifySignature(this, signature, verifyKey) ? IntegrityState.VALID_SIGNATURE : IntegrityState.FAILED_NOT_TRUSTED;
        } catch (Exception e) {
            return IntegrityState.FAILED_INTERNAL_FAULT;
        }
    }

    /**
     * Verifies any linked items to the item. This method will only verify that the list of provided items matches the
     * links in the item. The signature of the item will not be verified.
     * @param linkedItems A list of item where item links should be verified.
     * @return The integrity state of the verification.
     */
    public IntegrityState verifyLinkedItems(List<Item> linkedItems) {
        if (itemLinks == null) {
            itemLinks = getClaim(Claim.LNK);
        }
        if (itemLinks != null) {
            return ItemLink.verify(linkedItems, itemLinks);
        } else {
            return IntegrityState.FAILED_LINKED_ITEM_MISSING;
        }
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
        String cryptoSuite = !isLegacy() ? Dime.crypto.getDefaultSuiteName() : null;
        this.itemLinks.add(new ItemLink(item, cryptoSuite));
    }

    /**
     * Will cryptographically link item links of provided items to this item.
     * @param items The items to link.
     */
    public void setItemLinks(List<Item> items) {
        throwIfSigned();
        if (items == null) { throw new IllegalArgumentException("Items to link with must not be null."); }
        this.itemLinks = new ArrayList<>();
        String cryptoSuite = !isLegacy() ? Dime.crypto.getDefaultSuiteName() : null;
        for (Item item: items) {
            this.itemLinks.add(new ItemLink(item, cryptoSuite));
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
        throwIfSigned();
        getClaimMap().remove(Claim.LNK);
        this.itemLinks = null;
    }

    /**
     * Converts the item to legacy (before official Dime version 1).
     * @deprecated Legacy support will be removed in the next version.
     */
    @Deprecated
    public void convertToLegacy() {
        strip();
        if (getItemLinks() != null) {
            for (ItemLink link: getItemLinks()) {
                link.cryptoSuiteName = null;
            }
        }
        legacy = true;
    }

    /**
     * Checks if the item is legacy (before official Dime version 1).
     * @return True if legacy, false is not.
     * @deprecated Legacy support will be removed in the next version.
     */
    @Deprecated
    public boolean isLegacy() { return this.legacy; }

    /// PACKAGE-PRIVATE ///

    static final int MINIMUM_NBR_COMPONENTS = 2;
    static final int COMPONENTS_IDENTIFIER_INDEX = 0;
    static final int COMPONENTS_CLAIMS_INDEX = 1;

    @Deprecated
    void markAsLegacy() {
        legacy = true;
    }

    @SuppressWarnings("unchecked")
    static <T extends Item> T fromEncoded(String encoded) throws InvalidFormatException {
        try {
            int index = encoded.indexOf(Dime.COMPONENT_DELIMITER);
            if (index == -1) { return null; }
            Item item = Item.itemFromHeader(encoded.substring(0, index));
            item.decode(encoded);
            return (T) item;
        } catch (Exception e) {
            throw new RuntimeException("Unexpected and fatal exception caught while encoding item: ", e);
        }
    }

    String forExport() throws InvalidFormatException {
        return encoded(true);
    }

    /// PROTECTED ///

    protected String encoded;
    protected List<String> components;
    protected List<ItemLink> itemLinks;
    protected boolean isSigned = false;

    protected void setClaimValue(Claim claim, Object value) {
        getClaimMap().put(claim, value);
    }

    protected abstract boolean allowedToSetClaimDirectly(Claim claim);

    protected String exportClaims() throws IOException{
        return getClaimMap().toJSON();
    }

    protected final boolean hasClaims() {
        return getClaimMap().size() > 0;
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

    /// --- ENCODING/DECODING --- ///

    protected String encoded(boolean withSignature) throws InvalidFormatException {
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

    protected void customEncoding(StringBuilder builder) throws InvalidFormatException {
        builder.append(this.getHeader());
        builder.append(Dime.COMPONENT_DELIMITER);
        if (itemLinks != null && !itemLinks.isEmpty()) {
            getClaimMap().put(Claim.LNK, ItemLink.toEncoded(itemLinks));
        }
        try {
            builder.append(Utility.toBase64(this._claims.toJSON()));
        } catch (IOException e) {
            throw new InvalidFormatException("Unexpected exception while encoding item: " + e);
        }

    }

    protected final void decode(String encoded) throws InvalidFormatException {
        String[] array = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        if (array.length < getMinNbrOfComponents()) { throw new InvalidFormatException("Unexpected number of components for Dime item, expected at least " + getMinNbrOfComponents() + ", got " + array.length +"."); }
        if (array[Item.COMPONENTS_IDENTIFIER_INDEX].compareTo(getHeader()) != 0) { throw new InvalidFormatException("Unexpected Dime item identifier, expected: " + getHeader() + ", got " + array[Item.COMPONENTS_IDENTIFIER_INDEX] + "."); }
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

    protected abstract void customDecoding(List<String> components) throws InvalidFormatException;

    protected int getMinNbrOfComponents() {
        return Item.MINIMUM_NBR_COMPONENTS;
    }

    protected final void throwIfSigned() {
        if (isSigned()) {
            throw new IllegalStateException("Unable to complete operation, DiME item already signed.");
        }
    }

    /// PRIVATE ///

    private ClaimsMap _claims;
    private List<Signature> _signatures;
    @Deprecated
    private boolean legacy = false;

    private ClaimsMap getClaimMap() {
        if (this._claims != null) { return this._claims; }
        if (this.components != null && this.components.size() > Item.COMPONENTS_CLAIMS_INDEX) {
            byte[] jsonClaims = Utility.fromBase64(this.components.get(Item.COMPONENTS_CLAIMS_INDEX));
            this._claims = new ClaimsMap(new String(jsonClaims, StandardCharsets.UTF_8));
        } else {
            this._claims = new ClaimsMap();
        }
        return this._claims;
    }

    private static Item itemFromHeader(String header) throws Exception {
        var t = Item.classFromItemHeader(header);
        return (t != null) ? (Item) Objects.requireNonNull(t).getDeclaredConstructor().newInstance() : null;
    }

    private static Class<?> classFromItemHeader(String header) {
        switch (header) {
            case Data.HEADER: return Data.class;
            case Identity.HEADER: return Identity.class;
            case IdentityIssuingRequest.HEADER: return IdentityIssuingRequest.class;
            case Key.HEADER: return Key.class;
            case Message.HEADER: return Message.class;
            case Tag.HEADER: return Tag.class;
            default: return null;
        }
    }

}
