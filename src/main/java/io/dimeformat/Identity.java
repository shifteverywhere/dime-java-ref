//
//  Identity.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeDateException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.DimeIntegrityException;
import io.dimeformat.exceptions.DimeUntrustedIdentityException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public class Identity extends Item {

    /// PUBLIC ///
    public final static String TAG = "ID";

    @Override
    public String getTag() {
        return Identity.TAG;
    }

    public String getSystemName() {
        return this._claims.sys;
    }

    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    public UUID getSubjectId() {
        return this._claims.sub;
    }

    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    public byte[] getPublicKey() {
        return this._claims.pub;
    }

    // public [String, Any] getPrinciples() {}
    // public [String] getAmbit() {}

    public Identity getTrustChain() {
        return this._trustChain;
    }

    public boolean isSelfSigned() {
       return (this._claims.sub == this._claims.iss && this.hasCapability(Capability.SELF));
    }

    public synchronized static Identity getTrustedIdentity() {
        return Identity._trustedIdentity;
    }

    public synchronized static void setTrustedIdentity(Identity trustedIdentity) {
        Identity._trustedIdentity = trustedIdentity;
    }

    public void verifyTrust() throws DimeDateException, DimeUntrustedIdentityException {
        if (Identity._trustedIdentity == null) { throw new IllegalStateException("Unable to verify trust, no trusted identity set."); }
        Instant now = Instant.now();
        if (this.getIssuedAt().compareTo(now) > 0) { throw new DimeDateException("Identity is not yet valid, issued at date in the future."); }
        if (this.getIssuedAt().compareTo(this.getExpiresAt()) > 0) { throw new DimeDateException("Invalid expiration date, expires at before issued at."); }
        if (this.getExpiresAt().compareTo(now) < 0) { throw new DimeDateException("Identity has expired."); }
        if (Identity._trustedIdentity.getSystemName() != this.getSystemName()) { throw new DimeUntrustedIdentityException("Unable to trust identity, identity part of another system."); }
        if (this._trustChain != null) {
            this._trustChain.verifyTrust();
        }
        byte[] publicKey = (this._trustChain != null) ? this._trustChain.getPublicKey() : Identity._trustedIdentity.getPublicKey();
        try {
            Crypto.verifySignature(this._encoded, this._signature, Key.fromBase58Key(publicKey));
        } catch (DimeIntegrityException e) {
            throw new DimeUntrustedIdentityException("Identity cannot be trusted.");
        }
    }

    public boolean hasCapability(Capability capability) {
        return false;
    }

    public static Identity fromEncoded(String encoded) throws DimeFormatException {
       Identity identity = new Identity();
       identity.decode(encoded);
       return identity;
    }

    /// PACKAGE-PRIVATE ///

    Identity(String systemName, UUID subjectId, byte[] publicKey, Instant issuedAt, Instant expiresAt, UUID issuerId, Capability[] capabilities, Map<String, Object> principles, String[] ambit) {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        this._claims = new IdentityClaims(systemName,
                UUID.randomUUID(),
                subjectId,
                issuerId,
                issuedAt,
                expiresAt,
                publicKey,
                capabilities,
                principles,
                ambit);
    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("//" + Envelope._COMPONENT_DELIMITER);
        if (components.length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected "+ Identity._NBR_EXPECTED_COMPONENTS_MIN + " or " + Identity._NBR_EXPECTED_COMPONENTS_MAX +", got " + components.length + "."); }
        if (components[Identity._TAG_INDEX] != Identity.TAG) { throw new DimeFormatException("Unexpected item tag, expected: " + Identity.TAG + ", got " + components[Identity._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[Identity._CLAIMS_INDEX]);
        this._claims = new IdentityClaims(json);
        if (this._claims.sys == null || this._claims.sys.length() == 0) { throw new DimeFormatException("System name missing from identity."); }
        if (components.length == Identity._NBR_EXPECTED_COMPONENTS_MAX) { // There is also a trust chain identity
            byte[] issIdentity = Utility.fromBase64(components[Identity._CHAIN_INDEX]);
            this._trustChain = Identity.fromEncoded(new String(issIdentity, StandardCharsets.UTF_8));
        }
        this._encoded = encoded.substring(0, encoded.lastIndexOf(Envelope._COMPONENT_DELIMITER));
        this._signature = components[components.length - 1];
    }

    @Override
    protected String encode()  {
        if (this._encoded == null) {
            StringBuffer buffer = new StringBuffer();
            buffer.append(Identity.TAG);
            buffer.append(Envelope._COMPONENT_DELIMITER);
            buffer.append(Utility.toBase64(this._claims.toJSONString()));
            if (this._trustChain != null) {
                buffer.append(Envelope._COMPONENT_DELIMITER);
                buffer.append(Utility.toBase64(this._trustChain.encode() + Envelope._COMPONENT_DELIMITER + this._trustChain._signature));
            }
            this._encoded = buffer.toString();
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private class IdentityClaims {

        public String sys;
        public UUID uid;
        public UUID sub;
        public UUID iss;
        public Instant iat;
        public Instant exp;
        public byte[] pub;
        public JSONArray cap;
        public JSONObject pri;
        public JSONArray amb;

        public IdentityClaims(String sys, UUID uid, UUID sub, UUID iss, Instant iat, Instant exp, byte[] pub, Capability[] cap, Map<String, Object> pri, String[] amb) {
            this.sys = sys;
            this.uid = uid;
            this.sub = sub;
            this.iss = iss;
            this.iat = iat;
            this.exp = exp;
            this.pub = pub;
            if (cap != null && cap.length > 0) {
                this.cap = new JSONArray();
                for (Capability capability: cap) {
                    this.cap.put(capability.name().toLowerCase());
                }
            }
            this.pri = (pri != null && pri.size() > 0) ? new JSONObject(pri) : null;
            if (amb != null && amb.length > 0) {
                this.amb = new JSONArray();
                this.amb.putAll(cap);
            }
        }

        public IdentityClaims(byte[] json) {
            JSONObject jsonObject = new JSONObject(json);
            this.sys = jsonObject.getString("sys");
            this.uid = UUID.fromString(jsonObject.getString("uid"));
            this.sub = UUID.fromString(jsonObject.getString("sub"));
            this.iss = UUID.fromString(jsonObject.getString("iss"));
            this.iat = Instant.parse(jsonObject.getString("iat"));
            this.exp = Instant.parse(jsonObject.getString("exp"));
            this.pub = Utility.fromBase64(jsonObject.getString("pub"));
            this.cap = jsonObject.getJSONArray("cap");
            this.pri = jsonObject.getJSONObject("pri");
            this.amb = jsonObject.getJSONArray("amb");
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("sys", this.sys);
            jsonObject.put("uid", this.uid.toString());
            jsonObject.put("sub", this.sub.toString());
            jsonObject.put("iss", this.iss.toString());
            jsonObject.put("iat", this.iat.toString());
            jsonObject.put("exp", this.iat.toString());
            jsonObject.put("pub", "null");
            if (this.cap != null) { jsonObject.put("cap", this.cap); }
            if (this.pri != null) { jsonObject.put("pri", this.pri); }
            if (this.amb != null) { jsonObject.put("amb", this.amb); }
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

    private Identity() { }
}
