//
//  Identity.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Capability;
import io.dimeformat.exceptions.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.stream.Collectors.toList;

/**
 * Represents an entity inside a network, or equivalent system. May be self-issued or issued by a trusted entity (and
 * thus becomes part of a trusted chain).
 */
public class Identity extends Item {

    /// PUBLIC ///

    /** A tag identifying the Di:ME item type, part of the header. */
    public final static String TAG = "ID";

    /**
     * Returns the tag of the Di:ME item.
     * @return The tag of the item.
     */
    @Override
    public String getTag() {
        return Identity.TAG;
    }

    /**
     * Returns the name of the system or network that the entity belongs to. If issued by another entity and part of a
     * trust chain, then all entities will share the same system name.
     * @return The system name
     */
    public String getSystemName() {
        return this._claims.sys;
    }

    /**
     * Returns a unique identifier for the instance. This will be assigned when issuing an identity, but will change
     * with each re-issuing even if it is for the same entity.
     * @return A unique identifier, as a UUID.
     */
    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    /**
     * Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
     * specific entity.
     * @return The subject identifier assigned to an entity, as a UUID.
     */
    public UUID getSubjectId() {
        return this._claims.sub;
    }

    /**
     * Returns the issuer's subject identifier. The issuer is the entity that has issued the identity to another
     * entity. If this value is equal to the subject identifier, then this identity is self-issued.
     * @return The issuer identifier, as a UUID.
     */
    public UUID getIssuerId() {
        return this._claims.iss;
    }

    /**
     * The date and time when this identity was issued. Although, this date will most often be in the past, the identity
     * should not be used and not trusted before this date.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    /**
     * The date and time when the identity will expire, and should not be used and not trusted anymore.
     * @return A UTC timestamp, as an Instant.
     */
    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    /**
     * Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
     * public key or type IDENTITY.
     * @return A Key instance with a public key of type IDENTITY.
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
     * Returns a list of any capabilities given to an identity. These are requested by an entity and approved (and
     * potentially modified) by the issuing entity when issuing a new identity. Capabilities are usually used to
     * determine what an entity may do with its issued identity.
     * @return An immutable list of Capability instances.
     */
    public List<Capability> getCapabilities() {
        return this._claims.cap;
    }

    /**
     * Returns all principles assigned to an identity. These are key-value fields that further provide information about
     * the entity. Using principles are optional.
     * @return An immutable map of assigned principles (as <String, Object>).
     */
    public Map<String, Object> getPrinciples() {
        return (this._claims != null) ? Collections.unmodifiableMap(this._claims.pri) : null;
    }

    /**
     * Returns a list of ambits assigned to an identity. An ambit defines the scope, region or role where an identity
     * may be used.
     * @return An immutable list of ambits (as String instances).
     */
    public List<String> getAmbits() {
        return this._claims.amb;
    }

    /**
     * Returns a list of methods associated with an identity. The usage of this is normally context or application
     * specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
     * identity.
     * @return An immutable list of methods (as String instances).
     */
    public List<String> getMethods() {
        return this._claims.mtd;
    }

    /**
     * Returns the parent identity of a trust chain for an identity. This is the issuing identity.
     * @return Parent identity in a trust chain.
     */
    public Identity getTrustChain() {
        return this._trustChain;
    }

    /**
     * Returns if the identity has been self-issued. Self-issuing happens when the same entity issues its own identity.
     * @return true or false
     */
    public boolean isSelfIssued() {
       return (this._claims.sub == this._claims.iss && this.hasCapability(Capability.SELF));
    }

    /**
     * Returns the currently set trusted identity. This is normally the root identity of a trust chain.
     * @return An Identity instance.
     */
    public synchronized static Identity getTrustedIdentity() {
        return Identity._trustedIdentity;
    }

    /**
     * Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
     * instances. This is normally the root identity of a trust chain.
     * @param trustedIdentity The Identity instance to set as a trusted identity.
     */
    public synchronized static void setTrustedIdentity(Identity trustedIdentity) {
        Identity._trustedIdentity = trustedIdentity;
    }

    /**
     * Verifies if an Identity instance is valid and can be trusted. Will validate issued at and expires at dates, look
     * at a trust chain (if present) and verify the signature with the attached public key.
     * @throws DimeDateException If the issued at date is in the future, or if the expires at date is in the past.
     * @throws DimeUntrustedIdentityException If the trust of the identity could not be verified.
     */
    public void verifyTrust() throws DimeDateException, DimeUntrustedIdentityException {
        if (Identity._trustedIdentity == null) { throw new IllegalStateException("Unable to verify trust, no trusted identity set."); }
        Instant now = Instant.now();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Identity is not yet valid, issued at date in the future."); }
        if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Invalid expiration date, expires at before issued at."); }
        if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Identity has expired."); }
        if (Identity._trustedIdentity.getSystemName().compareTo(this.getSystemName()) != 0) { throw new DimeUntrustedIdentityException("Unable to trust identity, identity part of another system."); }
        if (this._trustChain != null) {
            this._trustChain.verifyTrust();
        }
        Key key = (this._trustChain != null) ? this._trustChain.getPublicKey() : Identity._trustedIdentity.getPublicKey();
        try {
            Crypto.verifySignature(this._encoded, this._signature, key);
        } catch (DimeIntegrityException e) {
            throw new DimeUntrustedIdentityException("Unable to verify trust of entity. (I1003)", e);
        }
    }

    /**
     * Will check if a particular capability has been given to an identity.
     * @param capability The capability to check for.
     * @return true or false.
     */
    public boolean hasCapability(Capability capability) {
       return this._claims.cap != null && this._claims.cap.contains(capability);
    }

    /**
     * Will check if an identity is within a particular ambit.
     * @param ambit The ambit to check for.
     * @return true or false.
     */
    public boolean hasAmbit(String ambit) {
        return this._claims.amb != null && this._claims.amb.contains(ambit);
    }

    /// PACKAGE-PRIVATE ///

    Identity() { }

    Identity(String systemName, UUID subjectId, Key subjectKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<Capability> capabilities, Map<String, Object> principles, List<String> ambits, List<String> methods) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        this._claims = new IdentityClaims(systemName,
                UUID.randomUUID(),
                subjectId,
                issuerId,
                issuedAt,
                expiresAt,
                subjectKey.getPublic(),
                capabilities,
                principles,
                ambits,
                methods);
    }

    void setTrustChain(Identity trustChain) {
        this._trustChain = trustChain;
    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected "+ Identity._NBR_EXPECTED_COMPONENTS_MIN + " or " + Identity._NBR_EXPECTED_COMPONENTS_MAX +", got " + components.length + "."); }
        if (components[Identity._TAG_INDEX].compareTo(Identity.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + Identity.TAG + ", got " + components[Identity._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Identity._CLAIMS_INDEX]);
        this._claims = new IdentityClaims(new String(json, StandardCharsets.UTF_8));
        if (this._claims.sys == null || this._claims.sys.length() == 0) { throw new DimeFormatException("System name missing from identity."); }
        if (components.length == Identity._NBR_EXPECTED_COMPONENTS_MAX) { // There is also a trust chain identity
            byte[] issIdentity = Utility.fromBase64(components[Identity._CHAIN_INDEX]);
            this._trustChain = Identity.fromEncodedIdentity(new String(issIdentity, StandardCharsets.UTF_8));
        }
        this._encoded = encoded.substring(0, encoded.lastIndexOf(Envelope._COMPONENT_DELIMITER));
        this._signature = components[components.length - 1];
    }

    @Override
    protected String encode()  {
        if (this._encoded == null) {
            StringBuilder builder = new StringBuilder();
            builder.append(Identity.TAG);
            builder.append(Envelope._COMPONENT_DELIMITER);
            builder.append(Utility.toBase64(this._claims.toJSONString()));
            if (this._trustChain != null) {
                builder.append(Envelope._COMPONENT_DELIMITER);
                builder.append(Utility.toBase64(this._trustChain.encode() + Envelope._COMPONENT_DELIMITER + this._trustChain._signature));
            }
            this._encoded = builder.toString();
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private static final class IdentityClaims {

        public String sys;
        public UUID uid;
        public UUID sub;
        public UUID iss;
        public Instant iat;
        public Instant exp;
        public String pub;
        public List<Capability> cap;
        public Map<String, Object> pri;
        public List<String> amb;
        public List<String> mtd;

        public IdentityClaims(String sys, UUID uid, UUID sub, UUID iss, Instant iat, Instant exp, String pub, List<Capability> cap, Map<String, Object> pri, List<String> amb, List<String> mtd) {
            this.sys = sys;
            this.uid = uid;
            this.sub = sub;
            this.iss = iss;
            this.iat = iat;
            this.exp = exp;
            this.pub = pub;
            this.cap = cap;
            this.pri = pri;
            this.amb = amb;
            this.mtd = mtd;
        }

        public IdentityClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.sys = (jsonObject.has("sys")) ? jsonObject.getString("sys") : null;
            this.uid = (jsonObject.has("uid")) ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.sub = (jsonObject.has("sub")) ? UUID.fromString(jsonObject.getString("sub")) : null;
            this.iss = (jsonObject.has("iss")) ? UUID.fromString(jsonObject.getString("iss")) : null;
            this.iat = (jsonObject.has("iat")) ? Instant.parse(jsonObject.getString("iat")) : null;
            this.exp = (jsonObject.has("exp")) ? Instant.parse(jsonObject.getString("exp")) : null;
            this.pub = (jsonObject.has("pub")) ? jsonObject.getString("pub") : null;
            if (jsonObject.has("cap")) {
                this.cap = new ArrayList<>();
                JSONArray array = jsonObject.getJSONArray("cap");
                for (int i = 0;  i < array.length(); i++) {
                    this.cap.add(Capability.valueOf(((String)array.get(i)).toUpperCase()));
                }
            }
            this.pri = (jsonObject.has("pri")) ? jsonObject.getJSONObject("pri").toMap() : null;
            this.amb = (jsonObject.has("amb")) ? jsonObject.getJSONArray("amb").toList().stream().filter(String.class::isInstance).map(String.class::cast).collect(toList()) : null;
            this.mtd = (jsonObject.has("mtd")) ? jsonObject.getJSONArray("mtd").toList().stream().filter(String.class::isInstance).map(String.class::cast).collect(toList()) : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.sys != null) { jsonObject.put("sys", this.sys); }
            if (this.uid != null) { jsonObject.put("uid", this.uid.toString()); }
            if (this.sub != null) { jsonObject.put("sub", this.sub.toString()); }
            if (this.iss != null) { jsonObject.put("iss", this.iss.toString()); }
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.exp != null) { jsonObject.put("exp", this.exp.toString()); }
            if (this.pub != null) { jsonObject.put("pub", this.pub); }
            if (this.cap != null) {
                String[] caps = new String[this.cap.size()];
                for (int i = 0; i < this.cap.size(); i++) {
                    caps[i] = this.cap.get(i).name().toLowerCase();
                }
                jsonObject.put("cap", caps);
            }
            if (this.pri != null) { jsonObject.put("pri", this.pri); }
            if (this.amb != null) { jsonObject.put("amb", this.amb); }
            if (this.mtd != null) { jsonObject.put("mtd", this.mtd); }
            return jsonObject.toString();
        }

    }

    private static final int _NBR_EXPECTED_COMPONENTS_MIN = 3;
    private static final int _NBR_EXPECTED_COMPONENTS_MAX = 4;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _CHAIN_INDEX = 2;

    private static Identity _trustedIdentity;

    private IdentityClaims _claims;
    private Identity _trustChain;

    private static Identity fromEncodedIdentity(String encoded) throws DimeFormatException {
        Identity identity = new Identity();
        identity.decode(encoded);
        return identity;
    }

}
