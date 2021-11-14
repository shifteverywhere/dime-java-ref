//
//  Identity.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.Date;
import java.util.UUID;

public class Identity extends Item {

    /// PUBLIC ///
    public final static String TAG = "ID";

    @Override
    public String getTag() {
        return Identity.TAG;
    }

    public String getSystemName() {
        return null;
    }

    @Override
    public UUID getUniqueId() {
        return null;
    }

    public UUID getSubjectId() {
        return null;
    }

    public Date getIssuedAt() {
        return null;
    }

    public Date getExpiresAt() {
        return null;
    }

    public String getPublicKey() {
        return null;
    }

    public Identity getTrustChain() {
        return this._trustChain;
    }

    // public [String, Any] getPrinciples() {}
    // public [String] getAmbit() {}

    public boolean isSelfSigned() {
        return false;
    }

    public synchronized static Identity getTrustedIdentity() {
        return Identity._trustedIdentity;
    }

    public synchronized static void setTrustedIdentity(Identity trustedIdentity) {
        Identity._trustedIdentity = trustedIdentity;
    }

    public void verifyTrust() {

    }

    public boolean hasCapability(Capability capability) {
        return false;
    }

    /*    protected static Key fromEncoded(String encoded) {
        return null;
    }*/

    /// PROTECTED ///

    protected Identity(String systemName, UUID subjectId, String publicKey, Date issuedAt, Date expiresAt, UUID issuerId, Capability[] capabilities /*, [String, Any] principles, [String] ambit*/) {

    }

    @Override
    protected void decode(String encoded) {

    }

    @Override
    protected String encode() {
        return null;
    }

    /// PRIVATE ///

    private static Identity _trustedIdentity;

    private Identity _trustChain;
}
