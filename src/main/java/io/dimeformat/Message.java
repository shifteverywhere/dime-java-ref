//
//  Message.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.KeyType;
import io.dimeformat.exceptions.*;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;

/**
 * A class that can be used to create secure and integrity protected messages, that can be sent to entities, who may
 * verify the integrity and trust of the message. Messages may also be end-to-end encrypted to protect the
 * confidentiality of the message payload.
 */
public class Message extends Item {

    /// PUBLIC ///

    /** A tag identifying the Di:ME item type, part of the header. */
    public final static String TAG = "MSG";

    /**
     * Returns the tag of the Di:ME item.
     * @return The tag of the item.
     */
    @Override
    public String getTag() {
        return Message.TAG;
    }

    /**
     * Returns a unique identifier for the instance. This will be generated at instance creation.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    /**
     * Returns the audience (receiver) identifier. This is optional, although required if encrypting the message
     * payload.
     * @return The audience identifier, as a UUID.
     */
    public UUID getAudienceId() {
        return this._claims.aud;
    }

    /**
     * Returns the issuer (sender/creator) identifier of the message.
     * @return The issuer identifier, as a UUID.
     */
    public UUID getIssuerId() {
        return this._claims.iss;
    }

    /**
     * The date and time when this message was created.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    /**
     * The date and time when the message will expire.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    /**
     * The identifier of the key that was used when encryption the message payload. This is optional, and usage is
     * application specific.
     * @return A key identifier, as a UUID.
     */
    public UUID getKeyId() {
        return this._claims.kid;
    }

    /**
     * Sets a key identifier, UUID. This is used to specify which particular key, most often in the position of the
     * audience, was used for the encryption of the payload. This is optional.
     * @param kid
     */
    public void setKeyId(UUID kid) {
        throwIfSigned();
        this._claims.kid = kid;
    }

    /**
     * Returns a public key that was included in the message. Normally this public key was used for a key exchange where
     * the shared key was used to encrypt the payload. This is optional.
     * @return A public key.
     */
    public Key getPublicKey() {
        if (this._claims.pub != null && this._claims.pub.length() > 0) {
            try {
                return Key.fromBase58Key(this._claims.pub);
            } catch (DimeFormatException e) { }
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
        this._claims.pub = publicKey.getPublic();
    }

    /**
     * If the message is linked to another Di:ME item, thus creating a cryptographic link between them, then this will
     * return the identifier, as a UUID, of the linked item. This is optional.
     * @return An identifier of a linked item, as a UUID.
     */
    public UUID getLinkedId() {
        if (this._claims.lnk != null) {
            String uuid = this._claims.lnk.split("//" + Envelope._COMPONENT_DELIMITER)[Message._LINK_UID_INDEX];
            return UUID.fromString(uuid);
        }
        return null;
    }

    /**
     * Returns the context that is attached to the message.
     * @return A String instance.
     */
    public String getContext() {
        return this._claims.ctx;
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
        if (context != null && context.length() > Envelope.MAX_CONTEXT_LENGTH) { throw new IllegalArgumentException("Context must not be longer than " + Envelope.MAX_CONTEXT_LENGTH + "."); }
        Instant iat = Instant.now();
        Instant exp = (validFor != -1) ? iat.plusSeconds(validFor) : null;
        this._claims = new MessageClaims(UUID.randomUUID(),
                audienceId,
                issuerId,
                iat,
                exp,
                null,
                null,
                null,
                context);
    }

    /**
     * Will sign the message with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
     * @param key The key to sign the item with, must be of type IDENTITY.
     * @throws DimeCryptographicException
     */
    @Override
    public void sign(Key key) throws DimeCryptographicException {
        if (this._payload == null) { throw new IllegalStateException("Unable to sign message, no payload added."); }
        super.sign(key);
    }

    /**
     * Verifies the signature of the message using a provided key.
     * @param key The key to used to verify the signature, must not be null.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeIntegrityException If the signature is invalid.
     */
    @Override
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (this._payload == null || this._payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        // Verify IssuedAt and ExpiresAt
        Instant now = Instant.now();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Issuing date in the future."); }
        if (this.getExpiresAt() != null) {
            if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Expiration before issuing date."); }
            if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Passed expiration date."); }
        }
        super.verify(key);
    }

    /**
     * Verifies the signature of the message using a provided key and verifies a linked item from the proved item. To
     * verify correctly the linkedItem must be the original item that the message was linked to.
     * @param key The key to used to verify the signature, must not be null.
     * @param linkedItem The item the message was linked to.
     * @throws DimeDateException If any problems with issued at and expires at dates.
     * @throws DimeFormatException If no item has been linked with the message.
     * @throws DimeIntegrityException If the signature is invalid.
     * @throws DimeCryptographicException If anything goes wrong.
     */
    public void verify(Key key, Item linkedItem) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        verify(key);
        if (linkedItem != null) {
            if (this._claims.lnk == null || this._claims.lnk.length() == 0) { throw new IllegalStateException("No link to Dime item found, unable to verify."); }
            String[] components = this._claims.lnk.split("\\" + Envelope._COMPONENT_DELIMITER);
            if (components.length != 3) { throw new DimeFormatException("Invalid data found in item link field."); }
            String msgHash = linkedItem.thumbprint();
            if (components[Message._LINK_ITEM_TYPE_INDEX].compareTo(linkedItem.getTag()) != 0
                    || components[Message._LINK_UID_INDEX].compareTo(linkedItem.getUniqueId().toString()) != 0
                    || components[Message._LINK_THUMBPRINT_INDEX].compareTo(msgHash) != 0) {
                throw new DimeIntegrityException("Failed to verify link Dime item (provided item did not match).");
            }
        }
    }

    /**
     * Sets the plain text payload of the message.
     * @param payload The payload to set.
     */
    public void setPayload(byte[] payload) {
        throwIfSigned();
        this._payload = Utility.toBase64(payload);
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
     * Returns the plain text payload of the message. If an encrypted payload have been set, then this will return the
     * encrypted payload.
     * @return The message payload.
     */
    public byte[] getPayload() {
        return Utility.fromBase64(this._payload);
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
        this._claims.lnk = item.getTag() + Envelope._COMPONENT_DELIMITER + item.getUniqueId().toString() + Envelope._COMPONENT_DELIMITER + item.thumbprint();
    }

    /// PACKAGE-PRIVATE ///

    Message() { }

    /// PROTECTED ///

    @Override
    protected String toEncoded() {
        if (this._signature == null) { throw new IllegalStateException("Unable to encode message, must be signed first."); }
        return super.toEncoded();
    }

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Message._NBR_EXPECTED_COMPONENTS) {
            throw new DimeFormatException("Unexpected number of components for identity issuing request, expected: " + Message._NBR_EXPECTED_COMPONENTS + ", got " + components.length +".");
        }
        if (components[Message._TAG_INDEX].compareTo(Message.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Message.TAG + ", got: " + components[Message._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Message._CLAIMS_INDEX]);
        this._claims = new MessageClaims(new String(json, StandardCharsets.UTF_8));
        this._payload = components[Message._PAYLOAD_INDEX];
        this._encoded = encoded.substring(0, encoded.lastIndexOf(Envelope._COMPONENT_DELIMITER));
        this._signature = components[components.length - 1];
    }

    @Override
    protected String encode() {
        if (this._encoded == null) {
            this._encoded = Message.TAG +
                    Envelope._COMPONENT_DELIMITER +
                    Utility.toBase64(this._claims.toJSONString()) +
                    Envelope._COMPONENT_DELIMITER +
                    this._payload;
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private static final class MessageClaims {

        public UUID uid;
        public UUID aud;
        public UUID iss;
        public Instant iat;
        public Instant exp;
        public UUID kid;
        public String pub;
        public String lnk;
        public String ctx;

        public MessageClaims(UUID uid, UUID aud, UUID iss, Instant iat, Instant exp, UUID kid, String pub, String lnk, String ctx) {
            this.uid = uid;
            this.aud = aud;
            this.iss = iss;
            this.iat = iat;
            this.exp = exp;
            this.kid = kid;
            this.pub = pub;
            this.lnk = lnk;
            this.ctx = ctx;
        }

        public MessageClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.uid = jsonObject.has("uid") ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.aud = jsonObject.has("aud") ? UUID.fromString(jsonObject.getString("aud")) : null;
            this.iss = jsonObject.has("iss") ? UUID.fromString(jsonObject.getString("iss")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.exp = jsonObject.has("exp") ? Instant.parse(jsonObject.getString("exp")) : null;
            this.kid = jsonObject.has("kid") ? UUID.fromString(jsonObject.getString("kid")) : null;
            this.pub = (jsonObject.has("pub")) ? jsonObject.getString("pub") : null;
            this.lnk = jsonObject.has("lnk") ? jsonObject.getString("lnk") : null;
            this.ctx = jsonObject.has("ctx") ? jsonObject.getString("ctx") : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("uid", this.uid.toString());
            if (this.aud != null) { jsonObject.put("aud", this.aud.toString()); }
            jsonObject.put("iss", this.iss.toString());
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.exp != null) { jsonObject.put("exp", this.exp.toString()); }
            if (this.kid != null) { jsonObject.put("kid", this.iss.toString()); }
            if (this.pub != null) { jsonObject.put("pub", this.pub); }
            if (this.lnk != null) { jsonObject.put("lnk", this.lnk); }
            if (this.ctx != null) { jsonObject.put("ctx", this.ctx); }
            return jsonObject.toString();
        }

    }

    private static final int _NBR_EXPECTED_COMPONENTS = 4;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _PAYLOAD_INDEX = 2;
    private static final int _LINK_ITEM_TYPE_INDEX = 0;
    private static final int _LINK_UID_INDEX = 1;
    private static final int _LINK_THUMBPRINT_INDEX = 2;

    private MessageClaims _claims;
    private String _payload;

}
