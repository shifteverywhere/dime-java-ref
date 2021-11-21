//
//  Envelope.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * An encapsulating object that can carry one or more Di:ME items. This is usually the format
 * that is exported and stored or transmitted. It will start with the header 'Di'.
 * Envelopes may be either anonymous or signed. An anonymous envelope, most frequently used,
 * is not cryptographically sealed, although the items inside normally are. A signed envelope
 * can contain one or more items and is itself also signed, it also has a small number of claims
 * attached to it.
 */
public class Envelope {

    /// PUBLIC ///

    /**
     * The maximum length that the context claim may hold.
     * This is also used for the context claim in messages.
     * */
    public static final int MAX_CONTEXT_LENGTH = 84;
    /** The standard envelope header. */
    public static final String HEADER = "Di";
    /** The current version of the implemented Di:ME specification. */
    public static final int DIME_VERSION = 0x01;

    /**
     * Returns the identifier of the issuer of the envelope.
     * Only applicable for signed envelopes.
     * @return A UUID instance.
     */
    public UUID getIssuerId() {
        return (this._claims != null) ? this._claims.iss : null;
    }

    /**
     * Returns the date in UTC when this envelope was issued.
     * Only applicable for signed envelopes.
     * @return An Instant instance.
     */
    public Instant getIssuedAt() {
        return (this._claims != null) ? this._claims.iat : null;
    }

    /**
     * Returns the context that is attached to the envelope.
     * Only applicable for signed envelopes.
     * @return A String instance.
     */
    public String getContext() {
        return (this._claims != null) ? this._claims.ctx : null;
    }

    /**
     * Returns any attached Di:ME items. This will be an array of Item instances
     * and may be cast by looking at the tag of the item (getTag).
     * @return An array of Item instance
     */
    public List<Item> getItems() {
        return (this._items != null) ? Collections.unmodifiableList(this._items) : null;
    }

    /**
     * Indicates if the envelope has a signature attached to it. This does not indicate
     * if the envelope is signed or anonymous, as a tobe signed envelope will return
     * false here before it is signed.
     * @return true or false
     */
    public boolean isSigned() {
        return (this._signature != null);
    }

    /**
     * Indicates if the envelope is anonymous (true) or if it is signed (false).
     * @return true or false
     */
    public boolean isAnonymous() {
        return (this._claims == null);
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
        if (context != null && context.length() > Envelope.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Envelope.MAX_CONTEXT_LENGTH + "."); }
        this._claims = new EnvelopeClaims(issuerId, Instant.now(), context);
    }

    /**
     * Imports an envelope from a Di:ME encoded string. This will not verify the envelope,
     * this has to be done by calling verify separately.
     * @param encoded The encoded Di:ME envelope to import.
     * @return The imported Envelope instance.
     * @throws DimeFormatException If the format of the encoded envelope is wrong.
     */
    public static Envelope importFromEncoded(String encoded) throws DimeFormatException {
        if (!encoded.startsWith(Envelope.HEADER)) { throw new DimeFormatException("Not a Dime envelope object, invalid header."); }
        String[] sections = encoded.split("\\" + Envelope._SECTION_DELIMITER);
        // 0: HEADER
        String[] components = sections[0].split("\\" + Envelope._COMPONENT_DELIMITER);
        Envelope envelope;
        if (components.length == 2) {
            byte[] json = Utility.fromBase64(components[1]);
            envelope = new Envelope(new String(json, StandardCharsets.UTF_8));
        } else if (components.length == 1) {
            envelope = new Envelope();
        } else {
            throw new DimeFormatException("Not a valid Di:ME envelope object, unexpected number of components in header, got: " + components.length + ", expected: 1 or 2.");
        }
        // 1 to LAST or LAST - 1
        int endIndex = (envelope.isAnonymous()) ? sections.length : sections.length - 1; // end index dependent on anonymous Di:ME or not
        ArrayList<Item> items = new ArrayList<>(endIndex - 1);
        for (int index = 1; index < endIndex; index++)
            items.add(Item.fromEncoded(sections[index]));
        envelope._items = items;
        if (envelope.isAnonymous()) {
            envelope._encoded = encoded;
        } else {
            envelope._encoded = encoded.substring(0, encoded.lastIndexOf(Envelope._SECTION_DELIMITER));
            envelope._signature = sections[sections.length - 1];
        }
        return envelope;
    }

    /**
     * Adds a Di:ME item (of type Item or any subclass thereof) to the envelope. For signed envelopes, this needs to be
     * done before signing the envelope.
     * @param item The Di:ME item to add.
     * @return Returns the Envelope instance for convenience.
     */
    public Envelope addItem(Item item) {
        if (this._signature != null) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        if (this._items == null) {
            this._items = new ArrayList<>();
        }
        this._items.add(item);
        return this;
    }

    /**
     * Adds a list of Di:ME items (of type Item or any subclass thereof) to the envelope. For signed envelopes, this
     * needs to be done before signing the envelope.
     * @param items The Di:ME items to add.
     * @return Returns the Envelope instance for convenience.
     */
    public Envelope setItems(List<Item> items) {
        if (this._signature != null) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        this._items = new ArrayList<>(items);
        return this;
    }

    /**
     * Signs the envelope using the provided key. The key must be of type IDENTITY. It is not possible to sign an
     * anonymous envelope. It is also not possible to sign an envelope if it already has been signed or does not
     * contain any Di:ME items.
     * @param key The key to use when signing.
     * @return Returns the Envelope instance for convenience.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public Envelope sign(Key key) throws DimeCryptographicException {
        if (this.isAnonymous()) { throw new IllegalStateException("Unable to sign, envelope is anonymous."); }
        if (this._signature != null) { throw new IllegalStateException("Unable to sign, envelope is already signed."); }
        if (this._items == null || this._items.size() == 0) { throw new IllegalStateException("Unable to sign, at least one item must be attached before signing an envelope."); }
        this._signature = Crypto.generateSignature(encode(), key);
        return this;
    }

    /**
     * Verifies the signature of the envelope using a base 58 encoded public key.
     * @param publicKey The base 58 encoded public key to use, must not be null.
     * @return Returns the Envelope instance for convenience.
     * @throws DimeIntegrityException If the signature is invalid.
     * @throws DimeFormatException If the format of the provided key is invalid.
     */
    public Envelope verify(String publicKey) throws DimeIntegrityException, DimeFormatException {
        if (publicKey == null || publicKey.length() == 0) { throw new IllegalArgumentException("Key must not be null or of length zero."); }
        return verify(new Key(publicKey));
    }

    /**
     * Verifies the signature of the envelope using a provided key.
     * @param key The key to used to verify the signature, must not be null.
     * @return Returns the Envelope instance for convenience.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    public Envelope verify(Key key) throws DimeIntegrityException {
        if (key == null || key.getPublic() == null) { throw new IllegalArgumentException("Key must not be null."); }
        if (this.isAnonymous()) { throw new IllegalStateException("Unable to verify, envelope is anonymous."); }
        if (this._signature == null) { throw new IllegalStateException("Unable to verify, envelope is not signed."); }
        Crypto.verifySignature(encode(), this._signature, key);
        return this;
    }

    /**
     * Exports the envelope to a Di:ME encoded string.
     * @return The Di:ME encoded representation of the envelope.
     */
    public String exportToEncoded() {
        if (!this.isAnonymous()) {
            if (this._signature == null) { throw new IllegalStateException("Unable to export, envelope is not signed."); }
            return encode() + Envelope._SECTION_DELIMITER + this._signature;
        } else {
            return encode();
        }
    }

    /**
     * Returns the thumbprint of the envelope. This may be used to easily identify an envelope or detect if an
     * envelope has been changed. This is created by securely hashing the envelope and will be unique and change as
     * soon as any content changes.
     * @return The hash of the envelope as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public String thumbprint() throws DimeCryptographicException {
        String encoded = encode();
        if (!this.isAnonymous()) {
            encoded += Envelope._SECTION_DELIMITER + this._signature;
        }
        return Envelope.thumbprint(encoded);
    }

    /**
     * Returns the thumbprint of a Di:ME encoded envelope string. This may be used to easily identify an envelope
     * or detect if an envelope has been changed. This is created by securely hashing the envelope and will be unique
     * and change as soon as any content changes. This will generate the same value as the instance method thumbprint
     * for the same (and unchanged) envelope.
     * @param encoded The Di:ME encoded envelope string.
     * @return The hash of the envelope as a hex string.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public static String thumbprint(String encoded) throws DimeCryptographicException {
        return Utility.toHex(Crypto.generateHash(encoded.getBytes(StandardCharsets.UTF_8)));
    }

    /// PACKAGE-PRIVATE ///

    static final String _COMPONENT_DELIMITER = ".";
    static final String _SECTION_DELIMITER = ":";

    /// PRIVATE ///

    private static final class EnvelopeClaims {

        public UUID iss;
        public Instant iat;
        public String ctx;

        public EnvelopeClaims(UUID iss,Instant iat, String ctx) {
            this.iss = iss;
            this.iat = iat;
            this.ctx = ctx;
        }

        public EnvelopeClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.iss = jsonObject.has("iss") ? UUID.fromString(jsonObject.getString("iss")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.ctx = jsonObject.has("ctx") ? jsonObject.getString("ctx") : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.iss != null) { jsonObject.put("iss", this.iss.toString()); }
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.ctx != null) { jsonObject.put("ctx", this.ctx); }
            return jsonObject.toString();
        }

    }

    private Envelope.EnvelopeClaims _claims;
    private ArrayList<Item> _items;
    private String _encoded;
    private String _signature;

    private Envelope(String json) {
        this._claims = new EnvelopeClaims(json);
    }

    private String encode() {
        if (this._encoded == null) {
            StringBuilder builder = new StringBuilder();
            builder.append(Envelope.HEADER);
            if (!this.isAnonymous()) {
                builder.append(Envelope._COMPONENT_DELIMITER);
                builder.append(Utility.toBase64(this._claims.toJSONString()));
            }
            for (Item item : this._items) {
                builder.append(Envelope._SECTION_DELIMITER);
                builder.append(item.toEncoded());
            }
            this._encoded = builder.toString();
        }
        return this._encoded;
    }

}
