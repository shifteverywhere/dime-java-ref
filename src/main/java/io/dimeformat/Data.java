//
//  Data.java
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

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * DiME item that carries a data payload. The payload may be any data.
 */
public class Data extends Item {

    /// PUBLIC ///

    /** The item type identifier for Di:ME Data items. */
    public static final String ITEM_IDENTIFIER = "DAT";

    @Override
    public String getItemIdentifier() {
        return Data.ITEM_IDENTIFIER;
    }

    /**
     * Returns the mime type associated with the data payload. This is optional.
     * @return A String instance.
     */
    public String getMIMEType() {
        return getClaim(Claim.MIM);
    }

    /**
     * Creates a new Data instance with the provided parameters.
     * @param issuerId The identifier of the issuer, must not be null.
     */
    public Data(UUID issuerId) {
        this(issuerId, -1, null);
    }

    /**
     * Creates a new Data instance with the provided parameters.
     * @param issuerId The identifier of the issuer, must not be null.
     * @param validFor Number of seconds the data item should be valid, if -1 is provided, then it will never expire.
     */
    public Data(UUID issuerId, long validFor) {
        this(issuerId, validFor, null);
    }

    /**
     * Creates a new Data instance with the provided parameters.
     * @param issuerId The identifier of the issuer, must not be null.
     * @param context The context to attach to the data item, may be null.
     */
    public Data(UUID issuerId, String context) {
        this(issuerId, -1, context);
    }

    /**
     * Creates a new Data instance with the provided parameters.
     * @param issuerId The identifier of the issuer, must not be null.
     * @param validFor Number of seconds the data item should be valid, if -1 is provided, then it will never expire.
     * @param context The context to attach to the data item, may be null.
     */
    public Data(UUID issuerId, long validFor, String context) {
        if (issuerId == null) { throw new IllegalArgumentException("Issuer identifier must not be null."); }
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        putClaim(Claim.UID, UUID.randomUUID());
        putClaim(Claim.ISS, issuerId);
        Instant iat = Utility.createTimestamp();
        putClaim(Claim.IAT, iat);
        if (validFor != -1) {
            Instant exp = iat.plusSeconds(validFor);
            putClaim(Claim.EXP, exp);
        }
        putClaim(Claim.CTX, context);
    }

    /**
     * Sets the data payload of the item.
     * @param payload The payload to set.
     */
    public void setPayload(byte[] payload) {
        setPayload(payload, null);
    }

    /**
     * Sets the data payload of the item.
     * @param payload The payload to set.
     * @param mimeType The MIME type of the payload, may be null.
     */
    public void setPayload(byte[] payload, String mimeType) {
        throwIfSigned();
        this.payload = Utility.toBase64(payload);
        putClaim(Claim.MIM, mimeType);
    }

    /**
     * Returns the data payload set in the item.
     * @return The message payload.
     */
    public byte[] getPayload() {
        return Utility.fromBase64(this.payload);
    }

    @Override
    public void sign(Key key) throws DimeCryptographicException {
        if (this.payload == null) { throw new IllegalStateException("Unable to sign item, no payload added."); }
        super.sign(key);
    }

    @Override
    public void verify(Key trustedKey, List<Item> linkedItems) throws VerificationException {
        if (this.payload == null || this.payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        super.verify(trustedKey, linkedItems);
    }

    @Override
    public String thumbprint() throws DimeCryptographicException {
        if (payload == null) { throw new IllegalStateException("Unable to generate thumbprint, no payload added."); }
        return super.thumbprint();
    }

    /// PACKAGE-PRIVATE ///

    Data() { }

    /// PROTECTED ///

    protected String payload;

    @Override
    protected boolean validClaim(Claim claim) {
        return claim != Claim.CAP && claim != Claim.KEY && claim != Claim.KID && claim != Claim.PRI && claim != Claim.PUB;
    }

    @Override
    protected void customDecoding(List<String> components) throws DimeFormatException {
        if (components.size() > Data.MAXIMUM_NBR_COMPONENTS) { throw new DimeFormatException("More components in item than expected, got " + components.size() + ", expected maximum " + Data.MAXIMUM_NBR_COMPONENTS); }
        this.payload = components.get(COMPONENTS_PAYLOAD_INDEX);
        this.isSigned = components.size() == Data.MAXIMUM_NBR_COMPONENTS;
    }

    @Override
    protected void customEncoding(StringBuilder builder) throws DimeFormatException {
        super.customEncoding(builder);
        builder.append(Dime.COMPONENT_DELIMITER);
        builder.append(this.payload);
    }

    @Override
    protected int getMinNbrOfComponents() {
        return Data.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final int MINIMUM_NBR_COMPONENTS = 3;
    private static final int MAXIMUM_NBR_COMPONENTS = MINIMUM_NBR_COMPONENTS + 1;
    private static final int COMPONENTS_PAYLOAD_INDEX = 2;

}
