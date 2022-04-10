//
//  Claims.java
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import org.json.JSONObject;
import java.time.Instant;
import java.util.*;

/**
 * Handles claims for Di:ME items.
 */
class ClaimsMap {

    public ClaimsMap() {
        this._claims = new HashMap<String, Object>();
        put(Claim.UID, UUID.randomUUID());
    }

    public ClaimsMap(UUID uid) {
        this._claims = new HashMap<String, Object>();
        put(Claim.UID, uid);
    }

    public ClaimsMap(String encoded) {
        this._claims = (HashMap) ClaimsMap.fromJSON(encoded);
    }

    public String toJSON() {
        JSONObject jsonObject = new JSONObject(_claims);
        return jsonObject.toString();
    }

    public <T> T get(Claim claim) {
        return (T)_claims.get(claim.toString());
    }

    public UUID getUUID(Claim claim) {
        Object object = get(claim);
        if (object == null) { return null; }
        if (object instanceof UUID) {
            return (UUID) object;
        } else if (object instanceof String) {
            UUID uuid = UUID.fromString((String) object);
            _claims.put(claim.toString(), uuid);
            return uuid;
        } else {
            throw new IllegalArgumentException("Claim with name " + claim + " is not a UUID object.");
        }
    }

    public Instant getInstant(Claim claim) {
        Object object = get(claim);
        if (object == null) { return null; }
        if (object instanceof Instant) {
            return (Instant) object;
        } else if (object instanceof String) {
            Instant instant = Instant.parse((String) object);
            _claims.put(claim.toString(), instant);
            return instant;
        } else {
            throw new IllegalArgumentException("Claim with name " + claim + " is not an Instant object.");
        }
    }

    public byte[] getBytes(Claim claim) {
        String string = get(claim);
        if (string == null) { return null; }
        return Base58.decode(string);
    }

    public void put(Claim claim, Object value) {
        if (value != null) {
            if (value instanceof byte[]) {
                _claims.put(claim.toString(), Base58.encode((byte[])value, null));
            } else {
                _claims.put(claim.toString(), value);
            }
        }
    }

    public void remove(Claim claim) {
        _claims.remove(claim.toString());
    }

    /// PRIVATE ///

    protected final HashMap _claims;

    private static Map fromJSON(String json) {
        JSONObject jsonObject = new JSONObject(json);
        return jsonObject.toMap();
    }

}