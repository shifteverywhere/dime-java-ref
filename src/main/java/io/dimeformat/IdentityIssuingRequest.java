//
//  Envelope.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;

import java.util.Date;
import java.util.UUID;

public class IdentityIssuingRequest extends Item {

    /// PUBLIC ///

    public static final long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60;
    public static final String TAG = "IIR";

    @Override
    public String getTag() {
        return IdentityIssuingRequest.TAG;
    }

    @Override
    public UUID getUniqueId() {
        return null;
    }

    public Date getIssuedAt() {
        return null;
    }

    public String getPublicKey() {
        return null;
    }

    // public [String, Any] getPrinciples() {}

    public static IdentityIssuingRequest generateIIR(Key key, Capability[] capabilities /*, [String, Any] principles*/) {
        return null;
    }

    public IdentityIssuingRequest verify() {
        return this;
    }

    public void verify(Key key) throws DimeDateException {
        super.verify(key);
    }

    public boolean wantsCapability(Capability capability) {
        return false;
    }

    public Identity issueIdentity(UUID subjectId, double validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambit) {
        return null;
    }

    public Identity selfIssueIdentity(UUID subjectId, double validFor, Key issueKey, String systemName, String[] ambit) {
        return null;
    }

    /*    protected static Key fromEncoded(String encoded) {
        return null;
    }*/

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {

    }

    @Override
    protected String encode() {
        return null;
    }

    /// PRIVATE ///

    private Capability[] _capabilities;

    private Identity issueNewIdentity(String systemName, UUID subjectId, double validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambit) {
        return null;
    }

    private void completeCapabilities(Capability[] allowedCapabilities, Capability[] requiredCapabilities, boolean isSelfIssue) {

    }
}
