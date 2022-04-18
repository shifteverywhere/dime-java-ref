//
//  Data.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import java.time.Instant;
import java.util.UUID;

/**
 * Di:ME item that carries a data payload. The payload may be any data.
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
        return claims.get(Claim.MIM);
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
        this.claims = new ClaimsMap();
        this.claims.put(Claim.ISS, issuerId);
        Instant iat = Utility.createTimestamp();
        this.claims.put(Claim.IAT, iat);
        if (validFor != -1) {
            Instant exp = iat.plusSeconds(validFor);
            this.claims.put(Claim.EXP, exp);
        }
        this.claims.put(Claim.CTX, context);
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
        this.claims.put(Claim.MIM, mimeType);
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
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (this.payload == null || this.payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        // Verify IssuedAt and ExpiresAt
        Instant now = Utility.createTimestamp();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Issuing date in the future."); }
        if (this.getExpiresAt() != null) {
            if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Expiration before issuing date."); }
            if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Passed expiration date."); }
        }
        super.verify(key);
    }

    /// PACKAGE-PRIVATE ///

    Data() { }

    /// PROTECTED ///

    protected String payload;

    @Override
    protected String customDecoding(String[] components, String encoded) throws DimeFormatException {
        if (components.length != Data.NBR_EXPECTED_COMPONENTS_UNSIGNED && components.length != Data.NBR_EXPECTED_COMPONENTS_SIGNED) {
            throw new DimeFormatException("Unexpected number of components for data item request, expected: " + Data.NBR_EXPECTED_COMPONENTS_UNSIGNED + " or " + Data.NBR_EXPECTED_COMPONENTS_SIGNED + ", got " + components.length +".");
        }
        payload = components[Data.COMPONENTS_PAYLOAD_INDEX];
        if (components.length == Data.NBR_EXPECTED_COMPONENTS_SIGNED) {
            signature = components[components.length - 1];
        }
        return encoded.substring(0, encoded.lastIndexOf(Dime.COMPONENT_DELIMITER));
    }

    @Override
    protected void customEncoding(StringBuilder builder) {
        super.customEncoding(builder);
        builder.append(Dime.COMPONENT_DELIMITER);
        builder.append(this.payload);
    }

    /// PRIVATE ///

    private static final int NBR_EXPECTED_COMPONENTS_UNSIGNED = 3;
    private static final int NBR_EXPECTED_COMPONENTS_SIGNED = NBR_EXPECTED_COMPONENTS_UNSIGNED + 1;
    private static final int COMPONENTS_PAYLOAD_INDEX = 2;

}
