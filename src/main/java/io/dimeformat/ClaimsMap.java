//
//  Claims.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.*;
import org.json.JSONException;
import org.json.JSONObject;
import org.webpki.jcs.JsonCanonicalizer;
import java.io.IOException;
import java.time.Instant;
import java.util.*;

/**
 * Handles claims for Di:ME items.
 */
class ClaimsMap {

    ClaimsMap() {
        this._claims = new HashMap<>();
    }

    ClaimsMap(String encoded) {
        this._claims = ClaimsMap.fromJSON(encoded);
    }

    String toJSON() throws IOException {
        if (_claims == null) { return null; }
        JSONObject jsonObject = new JSONObject(this._claims);
        JsonCanonicalizer jsonCanonicalizer = new JsonCanonicalizer(jsonObject.toString());
        return jsonCanonicalizer.getEncodedString();
    }

    int size() {
        return _claims != null ?_claims.size() : 0;
    }

    <T> T get(Claim claim) {
        if (_claims == null) { return null; }
        Object value;
        switch (claim) {
            // UUID
            case AUD:
            case ISS:
            case KID:
            case SUB:
            case UID:
                value = getUUID(claim);
                break;
            // Instant
            case EXP:
            case IAT:
                value = getInstant(claim);
                break;
            case LNK:
                value = getItemLinks(claim);
                break;
            // Default
            default:
                value = _claims.get(claim.toString());
                break;
        }
        return (T) value;
    }

    void put(Claim claim, Object value) {
        if (value != null) {
            if (_claims == null) { _claims = new HashMap<>(); }
            if (value instanceof byte[]) {
                _claims.put(claim.toString(), Base58.encode((byte[])value));
            } else {
                _claims.put(claim.toString(), value);
            }
        }
    }

    void remove(Claim claim) {
        if (_claims == null) { return; }
        _claims.remove(claim.toString());
    }

    Map<Claim, Object> copyClaims() {

        if (this._claims != null) {
            HashMap<Claim, Object> claims = new HashMap<>();
            for (String key: this._claims.keySet()) {
                Claim claim = Claim.valueOf(key.toUpperCase());
                claims.put(claim, this._claims.get(key));
            }
            return claims;
        }
        return null;
    }

    /// PRIVATE ///

    protected HashMap<String, Object> _claims;

    private static HashMap<String, Object> fromJSON(String json) {
        try {
            JSONObject jsonObject = new JSONObject(json);
            return (HashMap<String, Object>)jsonObject.toMap();
        } catch (JSONException e) {
            return null;
        }
    }

    private UUID getUUID(Claim claim) {
        Object object = _claims.get(claim.toString());
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

    private Instant getInstant(Claim claim) {
        Object object = _claims.get(claim.toString());
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

    private List<ItemLink> getItemLinks(Claim claim) {
        String string = (String) _claims.get(claim.toString());
        if (string == null || string.length() == 0) { return null; }
        try {
            return ItemLink.fromEncodedList(string);
        } catch (InvalidFormatException e) {
            return null;
        }
    }

}
