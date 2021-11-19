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

public class Message extends Item {

    /// PUBLIC ///
    public final static String TAG = "MSG";

    @Override
    public String getTag() {
        return Message.TAG;
    }

    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    public UUID getAudienceId() {
        return this._claims.aud;
    }

    public UUID getIssuerId() {
        return this._claims.iss;
    }

    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    public UUID getKeyId() {
        return this._claims.kid;
    }

    public void setKeyId(UUID kid) {
        throwIfSigned();
        this._claims.kid = kid;
    }

    public String getPublicKey() {
        return (this._claims.pub != null) ? Base58.encode(this._claims.pub, null) : null;
    }

    public void setPublicKey(String pub) {
        throwIfSigned();
        this._claims.pub = (pub != null) ? Base58.decode(pub) : null;
    }

    public UUID getLinkedId() {
        if (this._claims.lnk != null) {
            String uuid = this._claims.lnk.split("//" + Envelope._COMPONENT_DELIMITER)[Message._LINK_UID_INDEX];
            return UUID.fromString(uuid);
        }
        return null;
    }

    public Message(UUID issuerId) {
        this(null, issuerId, -1);
    }

    public Message(UUID issuerId, long validFor) {
        this(null, issuerId, validFor);
    }

    public Message(UUID audienceId, UUID issuerId, long validFor) {
        Instant iat = Instant.now();
        Instant exp = (validFor != -1) ? iat.plusSeconds(validFor) : null;
        this._claims = new MessageClaims(UUID.randomUUID(),
                audienceId,
                issuerId,
                iat,
                exp,
                null,
                null,
                null);
    }

    @Override
    public void sign(Key key) throws DimeCryptographicException {
        if (this._payload == null) { throw new IllegalStateException("Unable to sign message, no payload added."); }
        super.sign(key);
    }

    @Override
    public String toEncoded() {
        if (this._payload == null) { throw new IllegalStateException("Unable to encode message, no payload added."); }
        return super.toEncoded();
    }

    public static Message fromEncoded(String encoded) throws DimeFormatException {
        Message message = new Message();
        message.decode(encoded);
        return message;
    }

    @Override
    public void verify(Key key) throws DimeDateException, DimeIntegrityException {
        if (this._payload == null || this._payload.length() == 0) { throw new IllegalStateException("Unable to verify message, no payload added."); }
        // Verify IssuedAt and ExpiresAt
        Instant now = Instant.now();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Issuing date in the future."); }
        if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Expiration before issuing date."); }
        if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Passed expiration date."); }
        super.verify(key);
    }

    public void verify(String publicKey, Item linkedItem) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        verify(new Key(publicKey), linkedItem);
    }

    public void verify(Key key, Item linkedItem) throws DimeDateException, DimeFormatException, DimeIntegrityException, DimeCryptographicException {
        verify(key);
        if (linkedItem != null) {
            if (this._claims.lnk == null || this._claims.lnk.length() == 0) { throw new IllegalStateException("No link to Dime item found, unable to verify."); }
            String[] components = this._claims.lnk.split("\\" + Envelope._COMPONENT_DELIMITER);
            if (components == null || components.length != 3) { throw new DimeFormatException("Invalid data found in item link field."); }
            String msgHash = linkedItem.thumbprint();
            if (components[Message._LINK_ITEM_TYPE_INDEX].compareTo(linkedItem.getTag()) != 0
                    || components[Message._LINK_UID_INDEX].compareTo(linkedItem.getUniqueId().toString()) != 0
                    || components[Message._LINK_THUMBPRINT_INDEX].compareTo(msgHash) != 0) {
                throw new DimeIntegrityException("Failed to verify link Dime item (provided item did not match).");
            }
        }
    }

    public void setPayload(byte[] payload) {
        throwIfSigned();
        this._payload = Utility.toBase64(payload);
    }

    public void setPayload(byte[] payload, Key issuerKey, Key audienceKey) throws DimeKeyMismatchException, DimeCryptographicException {
        setPayload(payload, issuerKey, audienceKey, null);
    }

    /**
     * Will encrypt and attach a payload using a shared encryption key between the issuer and audience of a message.
     * The audience ID of the message must be set before attaching payloads that will be encrypted.
     * @param payload The payload to encrypt and attach to the message, must not be null and of length >= 1.
     * @param issuerKey This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.
     * @param audienceKey This is the key of the audience of the message, must be of type EXCHANGE, must not be null.
     * @param salt An optional salt that will be used for the encryption, must be the same when at encryption/decryption, may be null.
     * @throws DimeKeyMismatchException
     */
    public void setPayload(byte[] payload, Key issuerKey, Key audienceKey, byte[] salt) throws DimeKeyMismatchException, DimeCryptographicException {
        throwIfSigned();
        if (this.getAudienceId() == null) { throw new IllegalStateException("AudienceId must be set in the message for encrypted payloads."); }
        if (payload == null || payload.length == 0) { throw new IllegalArgumentException("Payload must not be null or empty."); }
        if (issuerKey == null || issuerKey.getPublic() == null) { throw new IllegalArgumentException("Unable to encrypt, issuer key must not be null."); }
        if (audienceKey == null || audienceKey.getPublic() == null) { throw new IllegalArgumentException("Unable to encrypt, audience key must not be null."); }
        if (issuerKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to encrypt, issuer key of invalid key type."); }
        if (audienceKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to encrypt, audience key invalid key type."); }
        byte[] info = Crypto.generateHash((issuerKey.getPublic() + this.getUniqueId().toString() + this.getAudienceId().toString()).getBytes(StandardCharsets.UTF_8));
        Key shared = Crypto.generateSharedSecret(issuerKey, audienceKey, salt, info);
        setPayload(Crypto.encrypt(payload, shared));
    }

    public byte[] getPayload() {
        return Utility.fromBase64(this._payload);
    }

    public byte[] getPayload(Key issuerKey, Key audienceKey) throws DimeFormatException, DimeKeyMismatchException, DimeCryptographicException {
        return getPayload(issuerKey, audienceKey, null);
    }

    public byte[] getPayload(Key issuerKey, Key audienceKey, byte[] salt) throws DimeFormatException, DimeKeyMismatchException, DimeCryptographicException {
        if (issuerKey == null || issuerKey.getPublic() == null) { throw new IllegalArgumentException("Provided issuer key may not be null."); }
        if (audienceKey == null || audienceKey.getPublic() == null) { throw new IllegalArgumentException("Provided audience key may not be null."); }
        if (this.getAudienceId() == null) { throw new DimeFormatException("AudienceId (aud) missing in message, unable to dectrypt payload."); }
        if (issuerKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to decrypt, invalid key type."); }
        if (audienceKey.getKeyType() != KeyType.EXCHANGE) { throw new IllegalArgumentException("Unable to decrypt, audience key invalid key type."); }
        byte[] info = Crypto.generateHash((issuerKey.getPublic() + this.getUniqueId().toString() + this.getAudienceId().toString()).getBytes(StandardCharsets.UTF_8));
        Key key = Crypto.generateSharedSecret(issuerKey, audienceKey, salt, info);
        return Crypto.decrypt(getPayload(), key);
    }

    public void linkItem(Item item) throws DimeCryptographicException {
        if (this.isSigned()) { throw new IllegalStateException("Unable to link item, message is already signed."); }
        if (item == null) { throw new IllegalArgumentException("Item to link with must not be null."); }
        this._claims.lnk = item.getTag() + Envelope._COMPONENT_DELIMITER + item.getUniqueId().toString() + Envelope._COMPONENT_DELIMITER + item.thumbprint();
    }

    /// PACKAGE-PRIVATE ///

    Message() { }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE || components.length != Message._NBR_EXPECTED_COMPONENTS_SIGNATURE) {
            throw new DimeFormatException("Unexpected number of components for identity issuing request, expected: " + Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE + " or " + Message._NBR_EXPECTED_COMPONENTS_SIGNATURE + ", got " + components.length +".");
        }
        if (components[Message._TAG_INDEX].compareTo(Message.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Message.TAG + ", got: " + components[Message._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Message._CLAIMS_INDEX]);
        this._claims = new MessageClaims(new String(json, StandardCharsets.UTF_8));
        this._payload = components[Message._PAYLOAD_INDEX];
        if (components.length == Message._NBR_EXPECTED_COMPONENTS_SIGNATURE) {
            this._signature = components[components.length - 1];
        }
    }

    @Override
    protected String encode() {
        if (this._encoded == null) {
            StringBuffer buffer = new StringBuffer();
            buffer.append(Message.TAG);
            buffer.append(Envelope._COMPONENT_DELIMITER);
            buffer.append(Utility.toBase64(this._claims.toJSONString()));
            buffer.append(Envelope._COMPONENT_DELIMITER);
            buffer.append(this._payload);
            this._encoded = buffer.toString();
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private class MessageClaims {

        public UUID uid;
        public UUID aud;
        public UUID iss;
        public Instant iat;
        public Instant exp;
        public UUID kid;
        public byte[] pub;
        public String lnk;

        public MessageClaims(UUID uid, UUID aud, UUID iss, Instant iat, Instant exp, UUID kid, byte[] pub, String lnk) {
            this.uid = uid;
            this.aud = aud;
            this.iss = iss;
            this.iat = iat;
            this.exp = exp;
            this.kid = kid;
            this.pub = pub;
            this.lnk = lnk;
        }

        public MessageClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.uid = jsonObject.has("uid") ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.aud = jsonObject.has("aud") ? UUID.fromString(jsonObject.getString("aud")) : null;
            this.iss = jsonObject.has("iss") ? UUID.fromString(jsonObject.getString("iss")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.exp = jsonObject.has("exp") ? Instant.parse(jsonObject.getString("exp")) : null;
            this.kid = jsonObject.has("kid") ? UUID.fromString(jsonObject.getString("kid")) : null;
            this.pub = jsonObject.has("pub") ? Utility.fromBase64(jsonObject.getString("pub")) : null;
            this.lnk = jsonObject.has("lnk") ? jsonObject.getString("lnk") : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("uid", this.uid.toString());
            if (this.aud != null) { jsonObject.put("aud", this.aud.toString()); }
            jsonObject.put("iss", this.iss.toString());
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.exp != null) { jsonObject.put("exp", this.exp.toString()); }
            if (this.kid != null) { jsonObject.put("kid", this.iss.toString()); }
            if (this.pub != null) { jsonObject.put("pub", Base58.encode(this.pub, null)); }
            if (this.lnk != null) { jsonObject.put("lnk", this.lnk); }
            return jsonObject.toString();
        }

    }

    private static final int _NBR_EXPECTED_COMPONENTS_SIGNATURE = 4;
    private static final int _NBR_EXPECTED_COMPONENTS_NO_SIGNATURE = 4;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _PAYLOAD_INDEX = 2;
    private static final int _LINK_ITEM_TYPE_INDEX = 0;
    private static final int _LINK_UID_INDEX = 1;
    private static final int _LINK_THUMBPRINT_INDEX = 2;

    private MessageClaims _claims;
    private String _payload;

}
