//
//  Envelope.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.Date;
import java.util.UUID;

public class Envelope {

    /// PUBLIC ///
    public static final int MAX_CONTEXT_LENGTH = 84;
    public static final String HEADER = "Di";

    public UUID getIssuerId() {
        return null;
    }

    public Date getIssuedAt() {
        return null;
    }

    public String getContext() {
        return null;
    }

    public Item[] getItems() {
        return null;
    }

    public boolean isSigned() {
        return this._signature != null;
    }

    public boolean isAnonymous() {
        return true;
    }

    public Envelope(UUID issuerId, String context) {

    }

    public static Envelope importFromEncoded(String encoded) {
        return null;
    }

    public Envelope addItem(Item item) {
        return this;
    }

    public Envelope setItems(Item[] items) {
        return this;
    }

    public Envelope sign(Key key) {
        return this;
    }

    public Envelope verify(String publicKey) {
        return verify(new Key(publicKey));
    }

    public Envelope verify(Key key) {
        return this;
    }

    public String exportToEncoded() {
        return null;
    }

    public String thumbprint() {
        String encoded = encode();
        if (!this.isAnonymous()) {
            encoded += Envelope._SECTION_DELIMITER + this._signature;
        }
        return Envelope.thumbprint(encoded);
    }

    public static String thumbprint(String encoded) {
        return null;
    }

    /// PROTECTED ///

    protected static final String _COMPONENT_DELIMITER = ".";
    protected static final String _SECTION_DELIMITER = ":";

    /// PRIVATE ///

    private Item[] _items;
    private String _encoded;
    private String _signature;

    private String encode() {
        return this._encoded;
    }

}
