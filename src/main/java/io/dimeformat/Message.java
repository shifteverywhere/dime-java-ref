//
//  Message.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * A class that can be used to create secure and integrity protected messages, that can be sent to entities, who may
 * verify the integrity and trust of the message. Messages may also be end-to-end encrypted to protect the
 * confidentiality of the message payload.
 */
public class Message extends Data {

    /// PUBLIC ///

    /** The item type identifier for Di:ME Message items. */
    public static final String ITEM_IDENTIFIER = "MSG";

    @Override
    public String getItemIdentifier() {
        return Message.ITEM_IDENTIFIER;
    }

    /**
     * Returns the audience (receiver) identifier. This is optional, although required if encrypting the message
     * payload.
     * @return The audience identifier, as a UUID.
     */
    public UUID getAudienceId() {
        return claims.getUUID(Claim.AUD);
    }

    /**
     * The identifier of the key that was used when encryption the message payload. This is optional, and usage is
     * application specific.
     * @return A key identifier, as a UUID.
     */
    public UUID getKeyId() {
        return claims.getUUID(Claim.KID);
    }

    /**
     * Sets a key identifier, UUID. This is used to specify which particular key, most often in the position of the
     * audience, was used for the encryption of the payload. This is optional.
     * @param kid The identifier of the key to set.
     */
    public void setKeyId(UUID kid) {
        throwIfSigned();
        if (kid != null) {
            claims.put(Claim.KID, kid);
        } else {
            claims.remove(Claim.KID);
        }
    }

    /**
     * Returns a public key that was included in the message. Normally this public key was used for a key exchange where
     * the shared key was used to encrypt the payload. This is optional.
     * @return A public key.
     */
    public Key getPublicKey() {
        String pub = claims.get(Claim.PUB);
        if (pub != null && pub.length() > 0) {
            try {
                return Key.fromBase58Key(pub);
            } catch (DimeFormatException ignored) { /* ignored */ }
        }
        return null;
    }

    /**
     * Sets a public key that will be included in the message. This may be a public key that was used to derive a shared
     * key used for encrypting the payload. This is optional.
     * @param publicKey The public key to set.
     */
    public void setPublicKey(Key publicKey) {
        throwIfSigned();
        if (publicKey != null) {
            claims.put(Claim.PUB, publicKey.getPublic());
        } else {
            claims.remove(Claim.PUB);
        }
    }

    /**
     * If the message is linked to another Di:ME item, thus creating a cryptographic link between them, then this will
     * return the identifier, as a UUID, of the linked item. This is optional.
     * @return An identifier of a linked item, as a UUID.
     */
    public UUID getLinkedId() {
        String lnk = claims.get(Claim.LNK);
        if (lnk != null && !lnk.isEmpty()) {
            String uuid = lnk.split("//" + Dime.COMPONENT_DELIMITER)[Message.LINK_UID_INDEX];
            return UUID.fromString(uuid);
        }
        return null;
    }

    /**
     * Creates a message from a specified issuer (sender).
     * @param issuerId The issuer identifier.
     */
    public Message(UUID issuerId) {
        this(null, issuerId, -1, null);
    }

    /**
     * Creates a message from a specified issuer (sender) and an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     */
    public Message(UUID issuerId, long validFor) {
        this(null, issuerId, validFor, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender).
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     */
    public Message(UUID audienceId, UUID issuerId) {
        this(audienceId, issuerId, -1, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration date.
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     */
    public Message(UUID audienceId, UUID issuerId, long validFor) {
        this(audienceId, issuerId, validFor, null);
    }

    /**
     * Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration date
     * and a context. The context may be anything and may be used for application specific purposes.
     * @param audienceId The audience identifier. Providing -1 as validFor will skip setting an expiration date.
     * @param issuerId The issuer identifier.
     * @param validFor The number of seconds that the message should be valid for, from the time of issuing.
     * @param context The context to attach to the message, may be null.
     */
    public Message(UUID audienceId, UUID issuerId, long validFor, String context) {
        if (context != null && context.length() > Dime.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Dime.MAX_CONTEXT_LENGTH + "."); }
        Instant iat = Utility.createTimestamp();
        Instant exp = (validFor != -1) ? iat.plusSeconds(validFor) : null;
        this.claims = new ClaimsMap();
        this.claims.put(Claim.AUD, audienceId);
        this.claims.put(Claim.ISS, issuerId);
        this.claims.put(Claim.IAT, iat);
        this.claims.put(Claim.EXP, exp);
        this.claims.put(Claim.CTX, context);
    }

    /**
     * Verifies the signature of the message using a provided key. The provided grace period will be used.
     * @param key The key to used to verify the signature, must not be null. The provided grace period will be used.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    @Override
    public void verify(Key key, long gracePeriod) throws DimeDateException, DimeIntegrityException {
        if (this.payload == null || this.payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        // Verify IssuedAt and ExpiresAt
        Instant now = Utility.createTimestamp();
        if (Utility.gracefulTimestampCompare(this.getIssuedAt(), now, gracePeriod) > 0) { throw new DimeDateException("Issuing date in the future."); }
        if (this.getExpiresAt() != null) {
            if (Utility.gracefulTimestampCompare(this.getIssuedAt(), this.getExpiresAt(), 0) > 0) { throw new DimeDateException("Expiration before issuing date."); }
            if (Utility.gracefulTimestampCompare(this.getExpiresAt(), now, gracePeriod) < 0) { throw new DimeDateException("Passed expiration date."); }
        }
        super.verify(key, gracePeriod);
    }

    /**
     * Verifies the signature of the message using a provided key and verifies a linked item from the proved item. To
     * verify correctly the linkedItem must be the original item that the message was linked to. No grace period will be
     * used.
     * @param key The key to used to verify the signature, must not be null.
     * @param linkedItem The item the message was linked to.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeFormatException If no item has been linked with the message.
     * @throws DimeIntegrityException If the signature is invalid.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public void verify(Key key, Item linkedItem) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        verify(key, linkedItem, 0);
    }

    /**
     * Verifies the signature of the message using a provided key and verifies a linked item from the proved item. To
     * verify correctly the linkedItem must be the original item that the message was linked to. The provided grace
     * period will be used.
     * @param key The key to used to verify the signature, must not be null.
     * @param linkedItem The item the message was linked to.
     * @param gracePeriod A grace period to used when evaluating timestamps, in seconds.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeFormatException If no item has been linked with the message.
     * @throws DimeIntegrityException If the signature is invalid.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public void verify(Key key, Item linkedItem, long gracePeriod) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        verify(key, gracePeriod);
        if (linkedItem != null) {
            String lnk = claims.get(Claim.LNK);
            if (lnk == null || lnk.isEmpty()) { throw new IllegalStateException("No link to Di:ME item found, unable to verify."); }
            String[] components = lnk.split("\\" + Dime.COMPONENT_DELIMITER);
            if (components.length != 3) { throw new DimeFormatException("Invalid data found in item link field."); }
            String msgHash = linkedItem.thumbprint();
            if (components[Message.LINK_ITEM_TYPE_INDEX].compareTo(linkedItem.getItemIdentifier()) != 0
                    || components[Message.LINK_UID_INDEX].compareTo(linkedItem.getUniqueId().toString()) != 0
                    || components[Message.LINK_THUMBPRINT_INDEX].compareTo(msgHash) != 0) {
                throw new DimeIntegrityException("Failed to verify link Dime item (provided item did not match).");
            }
        }
    }

    /**
     * Will encrypt and attach a payload using a shared encryption key between the issuer and audience of a message.
     * @param payload The payload to encrypt and attach to the message, must not be null and of length >= 1.
     * @param issuerKey This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.
     * @param audienceKey This is the key of the audience of the message, must be of type EXCHANGE, must not be null.
     * @throws DimeKeyMismatchException If provided keys are not of type EXCHANGE.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public void setPayload(byte[] payload, Key issuerKey, Key audienceKey) throws DimeKeyMismatchException, DimeCryptographicException {
        throwIfSigned();
        if (payload == null || payload.length == 0) { throw new IllegalArgumentException("Payload must not be null or empty."); }
        if (issuerKey == null) { throw new IllegalArgumentException("Unable to encrypt, issuer key must not be null."); }
        if (audienceKey == null) { throw new IllegalArgumentException("Unable to encrypt, audience key must not be null."); }
        Key shared = Crypto.generateSharedSecret(issuerKey, audienceKey);
        setPayload(Crypto.encrypt(payload, shared));
    }

    /**
     * Returns the decrypted message payload, if it is able to decrypt it.
     * @param issuerKey This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.
     * @param audienceKey This is the key of the audience of the message, must be of type EXCHANGE, must not be null.
     * @return The message payload.
     * @throws DimeKeyMismatchException If provided keys are not of type EXCHANGE.
     * @throws DimeCryptographicException If something goes wrong.
     */
    public byte[] getPayload(Key issuerKey, Key audienceKey) throws DimeKeyMismatchException, DimeCryptographicException {
        if (issuerKey == null || issuerKey.getPublic() == null) { throw new IllegalArgumentException("Provided issuer key may not be null."); }
        if (audienceKey == null || audienceKey.getPublic() == null) { throw new IllegalArgumentException("Provided audience key may not be null."); }
        if (issuerKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to decrypt, invalid key type."); }
        if (audienceKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to decrypt, audience key invalid key type."); }
        Key key = Crypto.generateSharedSecret(issuerKey, audienceKey);
        return Crypto.decrypt(getPayload(), key);
    }

    /**
     * Will cryptographically link a message to another Di:ME item. This may be used to prove a relationship between one
     * message and other item.
     * @param item The item to link to the message.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public void linkItem(Item item) throws DimeCryptographicException {
        if (this.isSigned()) { throw new IllegalStateException("Unable to link item, message is already signed."); }
        if (item == null) { throw new IllegalArgumentException("Item to link with must not be null."); }
        claims.put(Claim.LNK, item.getItemIdentifier() + Dime.COMPONENT_DELIMITER + item.getUniqueId().toString() + Dime.COMPONENT_DELIMITER + item.thumbprint());
    }

    /// PACKAGE-PRIVATE ///

    Message() { }

    /// PROTECTED ///

    @Override
    protected String forExport() {
        if (!isSigned()) { throw new IllegalStateException("Unable to encode message, must be signed first."); }
        return super.forExport();
    }

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Dime.COMPONENT_DELIMITER);
        if (components.length != Message.NBR_EXPECTED_COMPONENTS) {
            throw new DimeFormatException("Unexpected number of components for message item, expected: " + Message.NBR_EXPECTED_COMPONENTS + ", got " + components.length +".");
        }
        if (components[Message.TAG_INDEX].compareTo(Message.ITEM_IDENTIFIER) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Message.ITEM_IDENTIFIER + ", got: " + components[Message.TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Message.CLAIMS_INDEX]);
        claims = new ClaimsMap(new String(json, StandardCharsets.UTF_8));
        payload = components[Message.PAYLOAD_INDEX];
        this.encoded = encoded.substring(0, encoded.lastIndexOf(Dime.COMPONENT_DELIMITER));
        signature = components[components.length - 1];
    }

    /// PRIVATE ///

    private static final int NBR_EXPECTED_COMPONENTS = 4;
    private static final int TAG_INDEX = 0;
    private static final int CLAIMS_INDEX = 1;
    private static final int PAYLOAD_INDEX = 2;
    private static final int LINK_ITEM_TYPE_INDEX = 0;
    private static final int LINK_UID_INDEX = 1;
    private static final int LINK_THUMBPRINT_INDEX = 2;

}
