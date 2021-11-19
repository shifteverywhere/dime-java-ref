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
import io.dimeformat.exceptions.DimeUnsupportedProfileException;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;

public class Envelope {

    /// PUBLIC ///
    public static final int MAX_CONTEXT_LENGTH = 84;
    public static final String HEADER = "Di";

    public UUID getIssuerId() {
        return (this._claims != null) ? this._claims.iss : null;
    }

    public Instant getIssuedAt() {
        return (this._claims != null) ? this._claims.iat : null;
    }

    public String getContext() {
        return (this._claims != null) ? this._claims.ctx : null;
    }

    public Item[] getItems() {
        return (this._items != null) ? this._items.toArray(new Item[this._items.size()]) : null;
    }

    public boolean isSigned() {
        return (this._signature != null);
    }

    public boolean isAnonymous() {
        return (this._claims == null);
    }

    public Envelope() { }

    public Envelope(UUID issuerId) {
        this(issuerId, null);
    }

    public Envelope(UUID issuerId, String context) {
        if (context != null && context.length() > Envelope.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Envelope.MAX_CONTEXT_LENGTH + "."); }
        this._claims = new EnvelopeClaims(issuerId, Instant.now(), context);
    }

    public static Envelope importFromEncoded(String exported) throws DimeFormatException {
        if (!exported.startsWith(Envelope.HEADER)) { throw new DimeFormatException("Not a Dime envelope object, invalid header."); }
        String[] sections = exported.split("\\" + Envelope._SECTION_DELIMITER);
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
        ArrayList<Item> items = new ArrayList<Item>(endIndex - 1);
        for (int index = 1; index < endIndex; index++)
            items.add(Item.fromEncoded(sections[index]));
        envelope._items = items;
        if (envelope.isAnonymous()) {
            envelope._encoded = exported;
        } else {
            envelope._encoded = exported.substring(0, exported.lastIndexOf(Envelope._SECTION_DELIMITER));
            envelope._signature = sections[sections.length - 1];
        }
        return envelope;
    }

    public Envelope addItem(Item item) {
        if (this._signature != null) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        if (this._items == null) {
            this._items = new ArrayList<Item>();
        }
        this._items.add(item);
        return this;
    }

    public Envelope setItems(ArrayList<Item> items) {
        if (this._signature != null) { throw new IllegalStateException("Unable to set items, envelope is already signed."); }
        this._items = items;
        return this;
    }

    public Envelope sign(Key key) throws DimeUnsupportedProfileException, DimeCryptographicException {
        if (this.isAnonymous()) { throw new IllegalStateException("Unable to sign, envelope is anonymous."); }
        if (this._signature != null) { throw new IllegalStateException("Unable to sign, envelope is already signed."); }
        if (this._items == null || this._items.size() == 0) { throw new IllegalStateException("Unable to sign, at least one item must be attached before signing an envelope."); }
        this._signature = Crypto.generateSignature(encode(), key);
        return this;
    }

    public Envelope verify(String publicKey) throws DimeIntegrityException, DimeUnsupportedProfileException, DimeFormatException {
        return verify(new Key(publicKey));
    }

    public Envelope verify(Key key) throws DimeIntegrityException, DimeUnsupportedProfileException {
        if (this.isAnonymous()) { throw new IllegalStateException("Unable to verify, envelope is anonymous."); }
        if (this._signature == null) { throw new IllegalStateException("Unable to verify, envelope is not signed."); }
        Crypto.verifySignature(encode(), this._signature, key);
        return this;
    }

    public String exportToEncoded() {
        if (!this.isAnonymous()) {
            if (this._signature == null) { throw new IllegalStateException("Unable to export, envelope is not signed."); }
            return encode() + Envelope._SECTION_DELIMITER + this._signature;
        } else {
            return encode();
        }
    }

    public String thumbprint() throws DimeUnsupportedProfileException, DimeCryptographicException {
        String encoded = encode();
        if (!this.isAnonymous()) {
            encoded += Envelope._SECTION_DELIMITER + this._signature;
        }
        return Envelope.thumbprint(encoded);
    }

    public static String thumbprint(String encoded) throws DimeUnsupportedProfileException, DimeCryptographicException {
        return Utility.toHex(Crypto.generateHash(Profile.UNO, encoded.getBytes(StandardCharsets.UTF_8)));
    }

    /// PACKAGE-PRIVATE ///

    static final String _COMPONENT_DELIMITER = ".";
    static final String _SECTION_DELIMITER = ":";

    /// PRIVATE ///

    private class EnvelopeClaims {

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
            StringBuffer buffer = new StringBuffer();
            buffer.append(Envelope.HEADER);
            if (!this.isAnonymous()) {
                buffer.append(Envelope._COMPONENT_DELIMITER);
                buffer.append(Utility.toBase64(this._claims.toJSONString()));
            }
            for (Item item : this._items) {
                buffer.append(Envelope._SECTION_DELIMITER);
                buffer.append(item.toEncoded());
            }
            this._encoded = buffer.toString();
        }
        return this._encoded;
    }

}
