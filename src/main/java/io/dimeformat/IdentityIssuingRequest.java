//
//  Envelope.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.*;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

public class IdentityIssuingRequest extends Item {

    /// PUBLIC ///

    public static final long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60;
    public static final String TAG = "IIR";

    @Override
    public String getTag() {
        return IdentityIssuingRequest.TAG;
    }

    @Override
    public UUID getUniqueId() {
        return this._claims.uid;
    }

    public Instant getIssuedAt() {
        return this._claims.iat;
    }

    public String getPublicKey() {
        return this._claims.pub;
    }

    // public [String, Any] getPrinciples() {}

    public static IdentityIssuingRequest generateIIR(Key key) throws DimeUnsupportedProfileException {
        return generateIIR(key, null, null);
    }

    public static IdentityIssuingRequest generateIIR(Key key, Capability[] capabilities, Map<String, Object> principles) throws DimeUnsupportedProfileException {
        if (!Crypto.isSupportedProfile(key.getProfile())) { throw new IllegalArgumentException("Unsupported profile version."); }
        if (key.getKeyType() != KeyType.IDENTITY) { throw new IllegalArgumentException("Key of invalid type."); }
        if (key.getSecret() == null) { throw new IllegalArgumentException("Private key must not be null"); }
        if (key.getPublic() == null) { throw new IllegalArgumentException("Public key must not be null"); }
        IdentityIssuingRequest iir = new IdentityIssuingRequest();
        if (capabilities == null || capabilities.length == 0) {
            capabilities = new Capability[] { Capability.GENERIC };
        }
        iir._claims = new IdentityIssuingRequestClaims(UUID.randomUUID(),
                Instant.now(),
                key.getPublic(),
                capabilities,
                principles);
        iir._signature = Crypto.generateSignature(iir.encode(), key);
        return iir;
    }

    public IdentityIssuingRequest verify() throws DimeDateException, DimeIntegrityException, DimeUnsupportedProfileException, DimeFormatException {
        verify(Key.fromBase58Key(this._claims.pub));
        return this;
    }

    public void verify(Key key) throws DimeDateException, DimeIntegrityException, DimeUnsupportedProfileException {
        if (Instant.now().compareTo(this.getIssuedAt()) < 0) { throw new DimeDateException("An identity issuing request cannot have an issued at date in the future."); }
        super.verify(key);
    }

    public boolean wantsCapability(Capability capability) {
        return this._claims.cap.contains(capability);
    }

    public Identity issueIdentity(UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambit) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeUnsupportedProfileException {
        if (issuerIdentity == null) { throw new IllegalArgumentException("Issuer identity must not be null."); }
        return issueNewIdentity(issuerIdentity.getSystemName(), subjectId, validFor, issuerKey, issuerIdentity, allowedCapabilities, requiredCapabilities, ambit);
    }

    public Identity selfIssueIdentity(UUID subjectId, long validFor, Key issuerKey, String systemName, String[] ambit) throws DimeDateException, DimeCapabilityException, DimeUntrustedIdentityException, DimeUnsupportedProfileException {
        if (systemName == null || systemName.length() == 0) { throw new IllegalArgumentException("System name must not be null or empty."); }
        return issueNewIdentity(systemName, subjectId, validFor, issuerKey, null, null, null, ambit);

    }

    public static IdentityIssuingRequest fromEncoded(String encoded) throws DimeFormatException {
        IdentityIssuingRequest iir = new IdentityIssuingRequest();
        iir.decode(encoded);
        return iir;
    }

    /// PROTECTED ///

    @Override
    protected void decode(String encoded) throws DimeFormatException {
        String[] components = encoded.split("\\" + Envelope._COMPONENT_DELIMITER);
        if (components.length != IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE && components.length != IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE) { throw new DimeFormatException("Unexpected number of components for identity issuing request, expected " + IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE + " or  " + IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE + ", got " + components.length + "."); }
        if (components[IdentityIssuingRequest._TAG_INDEX].compareTo(IdentityIssuingRequest.TAG) != 0) { throw new DimeFormatException("Unexpected item tag, expected: " + IdentityIssuingRequest.TAG + ", got " + components[IdentityIssuingRequest._TAG_INDEX] + "."); }
        byte[] json = Utility.fromBase64(components[IdentityIssuingRequest._CLAIMS_INDEX]);
        this._claims = new IdentityIssuingRequestClaims(new String(json, StandardCharsets.UTF_8));
        if (components.length == _NBR_COMPONENTS_WITH_SIGNATURE) {
            this._encoded = encoded.substring(0, encoded.lastIndexOf(Envelope._COMPONENT_DELIMITER));
            this._signature = components[IdentityIssuingRequest._SIGNATURE_INDEX];
        }
    }

    @Override
    protected String encode() {
        if (this._encoded == null) {
            StringBuffer builder = new StringBuffer();
            builder.append(IdentityIssuingRequest.TAG);
            builder.append(Envelope._COMPONENT_DELIMITER);
            builder.append(Utility.toBase64(this._claims.toJSONString()));
            this._encoded = builder.toString();
        }
        return this._encoded;
    }

    /// PRIVATE ///

    private static class IdentityIssuingRequestClaims {

        public UUID uid;
        public Instant iat;
        public String pub;
        public List<Capability> cap;
        public JSONObject pri;

        public IdentityIssuingRequestClaims(UUID uid, Instant iat, String pub, Capability[] cap, Map<String, Object> pri) {
            this.uid = uid;
            this.iat = iat;
            this.pub = pub;
            this.cap = Arrays.asList(cap);
            this.pri = (pri != null && pri.size() > 0) ? new JSONObject(pri) : null;
        }

        public IdentityIssuingRequestClaims(String json) {
            JSONObject jsonObject = new JSONObject(json);
            this.uid = jsonObject.has("uid") ? UUID.fromString(jsonObject.getString("uid")) : null;
            this.iat = jsonObject.has("iat") ? Instant.parse(jsonObject.getString("iat")) : null;
            this.pub = jsonObject.has("pub") ? jsonObject.getString("pub"): null;
            if (jsonObject.has("cap")) {
                this.cap = new ArrayList<Capability>();
                JSONArray array = jsonObject.getJSONArray("cap");
                for (int i = 0;  i < array.length(); i++) {
                    this.cap.add(Capability.valueOf(((String)array.get(i)).toUpperCase()));
                }
            }
            this.pri = jsonObject.has("pri") ? jsonObject.getJSONObject("pri") : null;
        }

        public String toJSONString() {
            JSONObject jsonObject = new JSONObject();
            if (this.uid != null) { jsonObject.put("uid", this.uid.toString()); }
            if (this.iat != null) { jsonObject.put("iat", this.iat.toString()); }
            if (this.pub != null) { jsonObject.put("pub", this.pub); }
            if (this.cap != null) {
                String[] caps = new String[this.cap.size()];
                for (int i = 0; i < this.cap.size(); i++) {
                    caps[i] = this.cap.get(i).name().toLowerCase();
                }
                jsonObject.put("cap", caps);
            }
            if (this.pri != null) { jsonObject.put("pri", this.pri); }
            return jsonObject.toString();
        }

    }

    private static final int _NBR_COMPONENTS_WITHOUT_SIGNATURE = 2;
    private static final int _NBR_COMPONENTS_WITH_SIGNATURE = 3;
    private static final int _TAG_INDEX = 0;
    private static final int _CLAIMS_INDEX = 1;
    private static final int _SIGNATURE_INDEX = 2;

    private IdentityIssuingRequestClaims _claims;

    private Identity issueNewIdentity(String systemName, UUID subjectId, long validFor, Key issuerKey, Identity issuerIdentity, Capability[] allowedCapabilities, Capability[] requiredCapabilities, String[] ambit) throws DimeCapabilityException, DimeDateException, DimeUntrustedIdentityException, DimeUnsupportedProfileException {
        boolean isSelfSign = (issuerIdentity == null || this.getPublicKey() == issuerKey.getPublic());
        this.completeCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
        if (isSelfSign || issuerIdentity.hasCapability(Capability.ISSUE))
        {
            Instant now = Instant.now();
            Instant expires = now.plusSeconds(validFor);
            UUID issuerId = issuerIdentity != null ? issuerIdentity.getSubjectId() : subjectId;
            List<String> ambitList = (ambit != null) ? Arrays.asList(ambit) : null;
            Identity identity = new Identity(systemName, subjectId, this.getPublicKey(), now, expires, issuerId, this._claims.cap, null/*this._claims.pri*/, ambitList);
            if (Identity.getTrustedIdentity() != null && issuerIdentity != null && issuerIdentity.getSubjectId() != Identity.getTrustedIdentity().getSubjectId()) {
                issuerIdentity.verifyTrust();
                // The chain will only be set if this is not the trusted identity (and as long as one is set)
                identity.setTrustChain(issuerIdentity);
            }
            identity.sign(issuerKey);
            return identity;
        }
        throw new DimeCapabilityException("Issuing identity missing 'issue' capability.");
    }

    private void completeCapabilities(Capability[] allowedCapabilities, Capability[] requiredCapabilities, boolean isSelfIssue) {
        if (this._claims.cap == null) {
            this._claims.cap = new ArrayList<>();
            this._claims.cap.add(Capability.GENERIC);
        }
        if (this._claims.cap.size() == 0) { this._claims.cap.add(Capability.GENERIC); }
        if (isSelfIssue) {
            if (!this.wantsCapability(Capability.SELF)) {
                this._claims.cap = new ArrayList<Capability>(this._claims.cap);
                this._claims.cap.add(Capability.SELF);
            }
        }/* else {
            if (allowedCapabilities == null || allowedCapabilities.length == 0) { throw new IllegalArgumentException("Allowed capabilities must be defined to issue identity."); }

            ArrayList allowed = new ArrayList<Capability>();
            allowed.add(allowedCapabilities);



            this._claims.cap.

            if (this._capabilities.Except(allowedCapabilities).Count() > 0) { throw new IdentityCapabilityException("IIR contains one or more disallowed capabilities."); }
            if (requiredCapabilities != null && requiredCapabilities.Except(this._capabilities).Count() > 0) { throw new IdentityCapabilityException("IIR is missing one or more required capabilities."); }
        }*/
    }
}
