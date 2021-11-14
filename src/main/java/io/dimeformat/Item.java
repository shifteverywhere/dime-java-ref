//
//  Item.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.UUID;

public abstract class Item {

    /// PUBLIC ///

    public abstract String getTag();

    public abstract UUID getUniqueId();

    public boolean isSigned() {
        return this._signature != null;
    }

    public static Item importItem(String encoded) {
        return null;
    }

    public String exportItem() {
        return null;
    }

    public String toEncoded() {
        return null;
    }

    public static Item fromEncoded(String encoded) {
        return null;
    }

    public void sign(Key key) {

    }

    public String Thumbprint() {
        return Item.Thumbprint(this.toEncoded());
    }

    public static String Thumbprint(String encoded) {
        return null;
    }

    // internal static Type TypeFromTag(string iid)

    public void verify(String publicKey) {

    }

    public void verify(Key key) {

    }

    /// PROTECTED ///

    protected String _encoded;
    protected String _signature;

    protected abstract void decode(String encoded);

    protected abstract String encode();

    protected void throwIfSigned() {
        if (this.isSigned()) {
            throw new IllegalStateException("Unable to complete operation, Di:ME item already signed.");
        }
    }

}
