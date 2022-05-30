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
import io.dimeformat.enums.KeyUsage;
import io.dimeformat.exceptions.*;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
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
        return getClaims().getUUID(Claim.AUD);
    }

    /**
     * The identifier of the key that was used when encryption the message payload. This is optional, and usage is
     * application specific.
     * @return A key identifier, as a UUID.
     */
    public UUID getKeyId() {
        return getClaims().getUUID(Claim.KID);
    }

    /**
     * Sets a key identifier, UUID. This is used to specify which particular key, most often in the position of the
     * audience, was used for the encryption of the payload. This is optional.
     * @param kid The identifier of the key to set.
     */
    public void setKeyId(UUID kid) {
        throwIfSigned();
        if (kid != null) {
            getClaims().put(Claim.KID, kid);
        } else {
            getClaims().remove(Claim.KID);
        }
    }

    /**
     * Returns a public key that was included in the message. Normally this public key was used for a key exchange where
     * the shared key was used to encrypt the payload. This is optional.
     * @return A public key.
     */
    public Key getPublicKey() {
        String pub = getClaims().get(Claim.PUB);
        if (pub != null && pub.length() > 0) {
            try {
                return new Key(List.of(KeyUsage.EXCHANGE), pub, Claim.PUB);
            } catch (DimeCryptographicException ignored) { /* ignored */ }
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
            getClaims().put(Claim.PUB, publicKey.getPublic());
        } else {
            getClaims().remove(Claim.PUB);
        }
    }

    /**
     * If the message is linked to another Di:ME item, thus creating a cryptographic link between them, then this will
     * return the identifier, as a UUID, of the linked item. This is optional.
     * @return An identifier of a linked item, as a UUID.
     */
    public UUID getLinkedId() {
        String lnk = getClaims().get(Claim.LNK);
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
        getClaims().put(Claim.AUD, audienceId);
        getClaims().put(Claim.ISS, issuerId);
        getClaims().put(Claim.IAT, iat);
        getClaims().put(Claim.EXP, exp);
        getClaims().put(Claim.CTX, context);
    }

    @Override
    public String thumbprint() throws DimeCryptographicException {
        if (!isSigned()) { throw new IllegalStateException("Unable to generate thumbprint of message, must be signed first."); }
        return super.thumbprint();
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
        Key shared = Dime.crypto.generateSharedSecret(issuerKey, audienceKey, List.of(KeyUsage.ENCRYPT));
        setPayload(Dime.crypto.encrypt(payload, shared));
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
        Key key = Dime.crypto.generateSharedSecret(issuerKey, audienceKey, List.of(KeyUsage.ENCRYPT));
        return Dime.crypto.decrypt(getPayload(), key);
    }

    /// DEPRECATED ///

    /**
     * Will cryptographically link a message to another Di:ME item. This may be used to prove a relationship between one
     * message and other item.
     * @param item The item to link to the message.
     * @throws DimeCryptographicException If anything goes wrong.
     * @deprecated Will be removed in the future, use {#{@link Item#addItemLink(Item)}} instead.
     */
    @Deprecated
    public void linkItem(Item item) throws DimeCryptographicException {
        super.addItemLink(item);
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
     * @deprecated Will be removed in the future, use {#{@link Item#verify(Key, List)}} instead.
     */
    @Deprecated
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
     * @deprecated Will be removed in the future, use {#{@link Item#verify(Key, List, long)}} instead.
     */
    @Deprecated
    public void verify(Key key, Item linkedItem, long gracePeriod) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        super.verify(key, Arrays.asList(linkedItem), gracePeriod);
     }

    /// PACKAGE-PRIVATE ///

    /**
     * This is used to runtime instantiate new objects when parsing Di:ME envelopes.
     */
    Message() { }

    /// PROTECTED ///

    @Override
    protected String forExport() {
        if (!isSigned()) { throw new IllegalStateException("Unable to encode message, must be signed first."); }
        return super.forExport();
    }

    @Override
    protected void customDecoding(List<String> components) throws DimeFormatException {
        if (components.size() != Message.NBR_EXPECTED_COMPONENTS) {
            throw new DimeFormatException("Unexpected number of components for message item, expected: " + Message.NBR_EXPECTED_COMPONENTS + ", got " + components.size() +".");
        }
        super.customDecoding(components);
    }

    /// PRIVATE ///

    private static final int NBR_EXPECTED_COMPONENTS = 4;
    private static final int LINK_UID_INDEX = 1;

}
