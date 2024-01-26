//
//  Data.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import io.dimeformat.keyring.IntegrityState;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * DiME item that carries a data payload. The payload may be any data.
 */
public class Data extends Item {

    /// PUBLIC ///

    /** The item header for DiME Data items. */
    public static final String HEADER = "DAT";

    @Override
    public String getHeader() {
        return Data.HEADER;
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
    public void sign(Key signingKey) throws CryptographyException {
        if (this.payload == null) { throw new IllegalStateException("Unable to sign item, no payload added."); }
        super.sign(signingKey);
    }

    @Override
    public IntegrityState verify(Key verifyKey, List<Item> linkedItems) {
        if (this.payload == null || this.payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        return super.verify(verifyKey, linkedItems);
    }

    /// PACKAGE-PRIVATE ///

    Data() { }

    /// PROTECTED ///

    protected String payload;

    @Override
    protected boolean allowedToSetClaimDirectly(Claim claim) {
        return Data.allowedClaims.contains(claim);
    }

    @Override
    protected void customDecoding(List<String> components) throws InvalidFormatException {
        if (components.size() > Data.MAXIMUM_NBR_COMPONENTS) { throw new InvalidFormatException("More components in item than expected, got " + components.size() + ", expected maximum " + Data.MAXIMUM_NBR_COMPONENTS); }
        this.payload = components.get(COMPONENTS_PAYLOAD_INDEX);
        this.isSigned = components.size() == Data.MAXIMUM_NBR_COMPONENTS;
    }

    @Override
    protected void customEncoding(StringBuilder builder) throws InvalidFormatException {
        super.customEncoding(builder);
        builder.append(Dime.COMPONENT_DELIMITER);
        builder.append(this.payload);
    }

    @Override
    protected int getMinNbrOfComponents() {
        return Data.MINIMUM_NBR_COMPONENTS;
    }

    /// PRIVATE ///

    private static final List<Claim> allowedClaims = List.of(Claim.AMB, Claim.AUD, Claim.CMN, Claim.CTX, Claim.EXP, Claim.IAT, Claim.ISS, Claim.ISU, Claim.KID, Claim.MIM, Claim.MTD, Claim.SUB, Claim.SYS, Claim.UID);
    private static final int MINIMUM_NBR_COMPONENTS = 3;
    private static final int MAXIMUM_NBR_COMPONENTS = MINIMUM_NBR_COMPONENTS + 1;
    private static final int COMPONENTS_PAYLOAD_INDEX = 2;

}
