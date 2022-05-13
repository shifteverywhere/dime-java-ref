//
//  Item.java
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
import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

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
        return claims.getUUID(Claim.UID);
    }

    /**
     * Returns the identifier of the entity that created the Di:ME item (issuer). This may be optional depending on the
     * Di:ME item type.
     * @return The identifier of the issuer of the key.
     */
    public UUID getIssuerId() {
        return claims.getUUID(Claim.ISS);
    }

    /**
     * The date and time when this Di:ME item was issued. Although, this date will most often be in the past, the
     * item should not be processed if it is in the future.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return claims.getInstant(Claim.IAT);
    }

    /**
     * The date and time when the Di:ME item will expire, and should not be used and not trusted anymore after this
     * date.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getExpiresAt() {
        return claims.getInstant(Claim.EXP);
    }

    /**
     * Returns the context that is attached to the Di:ME item.
     * @return A String instance.
     */
    public String getContext() {
        return claims.get(Claim.CTX);
    }

    /**
     * Checks if the item has been signed or not.
     * @return true or false.
     */
    public boolean isSigned() {
        return (this.signature != null);
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
        envelope.addItem(this);
        return envelope.exportToEncoded();
    }

    /**
     * Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
     * @param key The key to sign the item with, must be of type IDENTITY.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public void sign(Key key) throws DimeCryptographicException {
        if (this.isSigned()) { throw new IllegalStateException("Unable to sign item, it is already signed. (I1003)"); }
        if (key == null || key.getSecret() == null) { throw new IllegalArgumentException("Unable to sign item, key for signing must not be null. (I1004)"); }
        this.signature = Crypto.generateSignature(encoded(false), key);
    }

    /**
     * Will remove a signature from an item.
     */
    public void strip() {
        this.encoded = null;
        this.signature = null;
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public String thumbprint() throws DimeCryptographicException {
        return Item.thumbprint(encoded(true));
    }

    /**
     * Returns the thumbprint of a Di:ME encoded item string. This may be used to easily identify an item or detect if
     * an item has been changed. This is created by securely hashing the item and will be unique and change as soon as
     * any content changes. This will generate the same value as the instance method thumbprint for the same (and
     * unchanged) item.
     * @param encoded The Di:ME encoded item string.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static String thumbprint(String encoded) throws DimeCryptographicException {
        return Utility.toHex(Crypto.generateHash(encoded.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Verifies the signature of the item using the key from the provided issuer identity. Will also verify that the
     * claim issuer (iss) matches the subject id (sub) of the provided identity. No grace period will be used when
     * comparing dates.
     * @param issuer The issuer identity to use while verifying.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    public void verify(Identity issuer) throws DimeDateException, DimeIntegrityException {
        this.verify(issuer, null, 0);
    }

    /**
     * Verifies the signature of the item using the key from the provided issuer identity. Will also verify that the
     * claim issuer (iss) matches the subject id (sub) of the provided identity. The provided grace period will be used
     * when verifying dates.
     * @param issuer The issuer identity to use while verifying.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    public void verify(Identity issuer, long gracePeriod) throws DimeDateException, DimeIntegrityException {
        verify(issuer, null, gracePeriod);
    }

    /**
     *  Verifies the signature of the item using the key from the provided issuer identity. Will also verify that the
     *  claim issuer (iss) matches the subject id (sub) of the provided identity. Any items provided in linkedItems will
     *  be verified with item links in the Dime item, if they cannot be verified correctly, then DimeIntegrityException
     *  will be thrown. Only items provided will be verified, any additional item links will be ignored. Providing items
     *  that are not linked will also result in a DimeIntegrityException being thrown. No grace period will be used when
     *  comparing dates.
     * @param issuer The issuer identity to use while verifying.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the item could not be verified to be integrity intact.
     */
    public void verify(Identity issuer, List<Item> linkedItems) throws DimeDateException, DimeIntegrityException {
        verify(issuer, linkedItems, 0);
    }

    /**
     * Verifies the signature of the item using the key from the provided issuer identity. Will also verify that the
     * claim issuer (iss) matches the subject id (sub) of the provided identity. Any items provided in linkedItems will
     * be verified with item links in the Dime item, if they cannot be verified correctly, then DimeIntegrityException
     * will be thrown. Only items provided will be verified, any additional item links will be ignored. Providing items
     * that are not linked will also result in a DimeIntegrityException being thrown. The provided grace period will be
     * used when verifying dates.
     * @param issuer The issuer identity to use while verifying.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the item could not be verified to be integrity intact.
     */
    public void verify(Identity issuer, List<Item> linkedItems, long gracePeriod) throws DimeDateException, DimeIntegrityException {
        if(issuer == null) { throw new IllegalArgumentException("Unable to verify, issuer must not be null."); }
        UUID issuerId = claims.getUUID(Claim.ISS);
        if (issuerId != null && !issuerId.equals(issuer.getSubjectId())) { throw new DimeIntegrityException("Unable to verify, subject id of provided issuer identity do not match item issuer id, expected: " + issuerId + ", got: " + issuer.getSubjectId()); }
        this.verify(issuer.getPublicKey(), linkedItems, gracePeriod);
    }

    /**
     * Verifies the signature of the item using a provided key. No grace period will be used when comparing dates.
     * @param key The key to used to verify the signature, must not be null.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the item could not be verified to be integrity intact.
     */
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        verify(key, null, 0);
    }

    /**
     * Verifies the signature of the item using a provided key. The provided grace period will be used when comparing
     * dates.
     * @param key The key to used to verify the signature, must not be null.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    public void verify(Key key, long gracePeriod) throws DimeDateException, DimeIntegrityException {
        verify(key, null, gracePeriod);
    }

    /**
     * Verifies the signature of the item using a provided key. Any items provided in linkedItems will be verified with
     * item links in the Dime item, if they cannot be verified correctly, then DimeIntegrityException will be thrown.
     * Only items provided will be verified, any additional item links will be ignored. Providing items that are not
     * linked will also result in a DimeIntegrityException being thrown.No grace period will be used when comparing
     * dates.
     * @param key The key to used to verify the signature, must not be null.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the item could not be verified to be integrity intact.
     */
    public void verify(Key key, List<Item> linkedItems) throws DimeDateException, DimeIntegrityException {
        verify(key, linkedItems, 0);
    }

    /**
     * Verifies the signature of the item using a provided key. Any items provided in linkedItems will be verified with
     * item links in the Dime item, if they cannot be verified correctly, then DimeIntegrityException will be thrown.
     * Only items provided will be verified, any additional item links will be ignored. Providing items that are not
     * linked will also result in a DimeIntegrityException being thrown. The provided grace period will be used when
     * comparing dates.
     * @param key The key to used to verify the signature, must not be null.
     * @param linkedItems A list of Dime items that should be verified towards any item links in the Dime item.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any dates (iat, exp) are outside the validity period.
     * @throws DimeIntegrityException If the item could not be verified to be integrity intact.
     */
    public void verify(Key key, List<Item> linkedItems, long gracePeriod) throws DimeDateException, DimeIntegrityException {
        if (!isSigned()) { throw new IllegalStateException("Unable to verify, item is not signed."); }
        verifyDates(gracePeriod); // Verify IssuedAt and ExpiresAt
        Crypto.verifySignature(encoded(false), this.signature, key);
        if (linkedItems != null) {
            if (itemLinks == null) {
                itemLinks = claims.getItemLinks(Claim.LNK);
            }
            if (itemLinks != null) {
                if (!ItemLink.verify(linkedItems, itemLinks)) {
                    throw new DimeIntegrityException("Unable to verify, provided linked items did not verify correctly.");
                }
            } else {
                throw new DimeIntegrityException("Unable to verify, no linked items found.");
            }
        }
    }

    /**
     * Will cryptographically link a tag to another Di:ME item.
     * @param item The item to link to the tag.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public void addItemLink(Item item) throws DimeCryptographicException {
        throwIfSigned();
        if (item == null) { throw new IllegalArgumentException("Item to link with must not be null."); }
        if (this.itemLinks == null) {
            this.itemLinks = new ArrayList<>();
        }
        this.itemLinks.add(new ItemLink(item));
    }

    public void setItemLinks(List<Item> items) throws DimeCryptographicException {
        throwIfSigned();
        if (items == null) { throw new IllegalArgumentException("Items to link with must not be null."); }
        this.itemLinks = new ArrayList<>();
        for (Item item: items) {
            this.itemLinks.add(new ItemLink(item));
        }
    }

    public List<ItemLink> getItemLinks() {
        if (this.itemLinks == null) {
            String lnk = this.claims.get(Claim.LNK);
            if (lnk != null && !lnk.isEmpty()) {
                try {
                    this.itemLinks = ItemLink.fromEncodedList(lnk);
                } catch (DimeFormatException e) {
                    // TODO: what to do here?
                }
            }
        }
        return this.itemLinks;
    }

    public void removeLinkItems() {
        if (claims.get(Claim.LNK) == null) return;
        throwIfSigned();
        claims.remove(Claim.LNK);
    }

    /// PACKAGE-PRIVATE ///

    static final int MINIMUM_NBR_COMPONENTS = 2;
    static final int COMPONENTS_TAG_INDEX = 0;
    static final int COMPONENTS_CLAIMS_INDEX = 1;

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

    String forExport() {
        return encoded(true);
    }

    /// PROTECTED ///

    protected String encoded;
    protected String signature;
    protected ClaimsMap claims;
    protected List<ItemLink> itemLinks;

    protected void verifyDates(long gracePeriod) throws DimeDateException {
        Instant now = Utility.createTimestamp();
        if (Utility.gracefulTimestampCompare(this.getIssuedAt(), now, gracePeriod) > 0) { throw new DimeDateException("Issuing date in the future."); }
        if (this.getExpiresAt() != null) {
            if (Utility.gracefulTimestampCompare(this.getIssuedAt(), this.getExpiresAt(), 0) > 0) { throw new DimeDateException("Expiration before issuing date."); }
            if (Utility.gracefulTimestampCompare(this.getExpiresAt(), now, gracePeriod) < 0) { throw new DimeDateException("Passed expiration date."); }
        }
    }

    protected String encoded(boolean withSignature) {
        if (this.encoded == null) {
            StringBuilder builder = new StringBuilder();
            customEncoding(builder);
            this.encoded = builder.toString();
        }
        if (withSignature && isSigned()) {
            return this.encoded + Dime.COMPONENT_DELIMITER + this.signature;
        }
        return this.encoded;
    }

    protected void customEncoding(StringBuilder builder) {
        builder.append(this.getItemIdentifier());
        builder.append(Dime.COMPONENT_DELIMITER);
        if (itemLinks != null && !itemLinks.isEmpty()) {
            this.claims.put(Claim.LNK, ItemLink.toEncoded(itemLinks));
        }
        builder.append(Utility.toBase64(this.claims.toJSON()));
    }

    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        if (components.length < Item.MINIMUM_NBR_COMPONENTS) { throw new DimeFormatException("Unexpected number of components for Di:ME item, expected at least " + Item.MINIMUM_NBR_COMPONENTS + ", got " + components.length +"."); }
        if (components[Item.COMPONENTS_TAG_INDEX].compareTo(getItemIdentifier()) != 0) { throw new DimeFormatException("Unexpected Di:ME item tag, expected: " + getItemIdentifier() + ", got " + components[Item.COMPONENTS_TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Item.COMPONENTS_CLAIMS_INDEX]);
        claims = new ClaimsMap(new String(json, StandardCharsets.UTF_8));
        this.encoded = customDecoding(components, encoded);
    }

    protected String customDecoding(String[] components, String encoded) throws DimeFormatException {
        return encoded;
    }

    protected void throwIfSigned() {
        if (this.isSigned()) {
            throw new IllegalStateException("Unable to complete operation, Di:ME item already signed.");
        }
    }

    /// PRIVATE ///

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
