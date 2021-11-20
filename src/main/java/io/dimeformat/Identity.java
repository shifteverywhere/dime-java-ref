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

    public UUID getIssuerId() {
        return this._claims.iss;
    }

    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    public Instant getExpiresAt() {
        return this._claims.exp;
    }

    public String getPublicKey() {
        return this._claims.pub;
    }

    public List<Capability> getCapabilities() {
        return this._claims.cap;
    }

    public Map<String, Object> getPrinciples() {
        return (this._claims != null) ? Collections.unmodifiableMap(this._claims.pri) : null;
    }

    public List<String> getAmbits() {
        return this._claims.amb;
    }

    public List<String> getMethods() {
        return this._claims.mtd;
    }

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
        if (Identity._trustedIdentity.getSystemName().compareTo(this.getSystemName()) != 0) { throw new DimeUntrustedIdentityException("Unable to trust identity, identity part of another system."); }
        if (this._trustChain != null) {
            this._trustChain.verifyTrust();
        }
        String publicKey = (this._trustChain != null) ? this._trustChain.getPublicKey() : Identity._trustedIdentity.getPublicKey();
        try {
            Crypto.verifySignature(this._encoded, this._signature, Key.fromBase58Key(publicKey));
        } catch (DimeIntegrityException | DimeFormatException e) {
            throw new DimeUntrustedIdentityException("Unable to verify trust of entity. (I1003)", e);
        }
    }

    public boolean hasCapability(Capability capability) {
       return (this._claims.cap != null) ? this._claims.cap.contains(capability) : false;
    }

    public boolean hasAmbit(String ambit) {
        return (this._claims.amb != null) ? this._claims.amb.contains(ambit) : false;
    }

    public static Identity fromEncoded(String encoded) throws DimeFormatException {
       Identity identity = new Identity();
       identity.decode(encoded);
       return identity;
    }

    /// PACKAGE-PRIVATE ///

    Identity() { }

    Identity(String systemName, UUID subjectId, String publicKey, Instant issuedAt, Instant expiresAt, UUID issuerId, List<Capability> capabilities, Map<String, Object> principles, List<String> ambits, List<String> methods) {
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
                this.cap = new ArrayList<Capability>();
                JSONArray array = jsonObject.getJSONArray("cap");
                for (int i = 0;  i < array.length(); i++) {
                    this.cap.add(Capability.valueOf(((String)array.get(i)).toUpperCase()));
                }
            }
            this.pri = (jsonObject.has("pri")) ? jsonObject.getJSONObject("pri").toMap() : null;
            this.amb = (jsonObject.has("amb")) ? (List<String>)(Object)jsonObject.getJSONArray("amb").toList() : null;
            this.mtd = (jsonObject.has("mtd")) ? (List<String>)(Object)jsonObject.getJSONArray("mtd").toList() : null;
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

}
