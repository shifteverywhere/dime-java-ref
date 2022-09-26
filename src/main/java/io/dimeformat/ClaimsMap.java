//
//  Claims.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.*;
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
        JSONObject jsonObject = new JSONObject(this._claims);
        JsonCanonicalizer jsonCanonicalizer = new JsonCanonicalizer(jsonObject.toString());
        return jsonCanonicalizer.getEncodedString();
    }

    int size() {
        return _claims.size();
    }

    <T> T get(Claim claim) {
        return (T)_claims.get(claim.toString());
    }

    UUID getUUID(Claim claim) {
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

    Instant getInstant(Claim claim) {
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

    byte[] getBytes(Claim claim) {
        String string = get(claim);
        if (string == null) { return null; }
        return Base58.decode(string);
    }

    Key getKey(Claim claim, List<Key.Use> use) {
        String string = get(claim);
        if (string == null || string.length() == 0) { return null; }
        try {
            return new Key(use, string, claim);
        } catch (DimeCryptographicException ignored) {
            return null;
        }
    }

    List<ItemLink> getItemLinks(Claim claim) {
        String string = get(claim);
        if (string == null || string.length() == 0) { return null; }
        try {
            return ItemLink.fromEncodedList(string);
        } catch (DimeFormatException e) {
            return null;
        }
    }

    void put(Claim claim, Object value) {
        if (value != null) {
            if (value instanceof byte[]) {
                _claims.put(claim.toString(), Base58.encode((byte[])value));
            } else {
                _claims.put(claim.toString(), value);
            }
        }
    }

    void remove(Claim claim) {
        _claims.remove(claim.toString());
    }

    /// PRIVATE ///

    protected final HashMap<String, Object> _claims;

    private static HashMap<String, Object> fromJSON(String json) {
        JSONObject jsonObject = new JSONObject(json);
        return (HashMap<String, Object>)jsonObject.toMap();
    }

}
