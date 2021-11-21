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

public abstract class Item {

    /// PUBLIC ///

    public abstract String getTag();

    public abstract UUID getUniqueId();

    public boolean isSigned() {
        return (this._signature != null);
    }

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

    public String exportToEncoded() {
        Envelope envelope = new Envelope();
        envelope.addItem(this);
        return envelope.exportToEncoded();
    }

    public void sign(Key key) throws DimeCryptographicException {
        if (this.isSigned()) { throw new IllegalStateException("Unable to sign item, it is already signed. (I1003)"); }
        if (key == null || key.getSecret() == null) { throw new IllegalArgumentException("Unable to sign item, key for signing must not be null. (I1004)"); }
        this._signature = Crypto.generateSignature(encode(), key);
    }

    public String thumbprint() throws DimeCryptographicException {
        return Item.thumbprint(this.toEncoded());
    }

    public static String thumbprint(String encoded) throws DimeCryptographicException {
        return Utility.toHex(Crypto.generateHash(encoded.getBytes(StandardCharsets.UTF_8)));
    }

    public String toEncoded() {
        if (this.isSigned()) {
            return encode() + Envelope._COMPONENT_DELIMITER + this._signature;
        }
        return encode();
    }

    private static Class<?> classFromTag(String tag) {
        return switch (tag) {
            case Identity.TAG -> Identity.class;
            case IdentityIssuingRequest.TAG -> IdentityIssuingRequest.class;
            case Message.TAG -> Message.class;
            case Key.TAG -> Key.class;
            default -> null;
        };
    }

    public void verify(String publicKey) throws DimeDateException, DimeIntegrityException, DimeFormatException {
        verify(new Key(publicKey));
    }

    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (!this.isSigned()) { throw new IllegalStateException("Unable to verify, item is not signed."); }
        Crypto.verifySignature(encode(), this._signature, key);
    }

    /// PACKAGE-PRIVATE ///

    @SuppressWarnings("unchecked")
    static <T extends Item> T fromEncoded(String encoded) throws DimeFormatException {
        try {
            var t = Item.classFromTag(encoded.substring(0, encoded.indexOf(Envelope._COMPONENT_DELIMITER)));
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

    protected String _encoded;
    protected String _signature;

    protected abstract void decode(String encoded) throws DimeFormatException;

    protected abstract String encode();

    protected void throwIfSigned() {
        if (this.isSigned()) {
            throw new IllegalStateException("Unable to complete operation, Di:ME item already signed.");
        }
    }

}
