//
//  Item.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Base class for any other type of Di:ME items that can be included inside an Envelope instance. */
public abstract class Item {

    /// PUBLIC ///

    /**
     * Returns the tag of the Di:ME item. Must be overridden by any subclass.
     * @return The tag of the item.
     */
    public abstract String getTag();

    /**
     * Returns a unique identifier for the instance. This will be generated at instance creation.
     * @return A unique identifier, as a UUID. Must be overridden by any subclass.
     */
    public abstract UUID getUniqueId();

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
        this.signature = Crypto.generateSignature(encode(), key);
    }

    /**
     * Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has been
     * changed. This is created by securely hashing the item and will be unique and change as soon as any content
     * changes.
     * @return The hash of the item as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public String thumbprint() throws DimeCryptographicException {
        return Item.thumbprint(this.toEncoded());
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
     * Verifies the signature of the item using a provided key.
     * @param key The key to used to verify the signature, must not be null.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (!this.isSigned()) { throw new IllegalStateException("Unable to verify, item is not signed."); }
        Crypto.verifySignature(encode(), this.signature, key);
    }

    /// PACKAGE-PRIVATE ///

    @SuppressWarnings("unchecked")
    static <T extends Item> T fromEncoded(String encoded) throws DimeFormatException {
        try {
            var t = Item.classFromTag(encoded.substring(0, encoded.indexOf(Envelope.COMPONENT_DELIMITER)));
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

    /// PROTECTED ///

    protected String encoded;
    protected String signature;

    protected String toEncoded() {
        if (this.isSigned()) {
            return encode() + Envelope.COMPONENT_DELIMITER + this.signature;
        }
        return encode();
    }

    protected abstract void decode(String encoded) throws DimeFormatException;

    protected abstract String encode();

    protected void throwIfSigned() {
        if (this.isSigned()) {
            throw new IllegalStateException("Unable to complete operation, Di:ME item already signed.");
        }
    }

    /// PRIVATE ///

    private static Class<?> classFromTag(String tag) {
        switch (tag) {
            case Identity.TAG: return Identity.class;
            case IdentityIssuingRequest.TAG: return IdentityIssuingRequest.class;
            case Message.TAG: return Message.class;
            case Key.TAG: return Key.class;
            default: return null;
        }
    }

}
