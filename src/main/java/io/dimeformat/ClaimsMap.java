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

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyUsage;
import io.dimeformat.exceptions.*;
import org.json.JSONObject;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Handles claims for Di:ME items.
 */
class ClaimsMap {

    public ClaimsMap() {
        this._claims = new HashMap<>();
    }

    public List<String> sort() {
        Set<String> keys = this._claims.keySet();
        Stream<String> sorted = keys.stream().sorted();
        return sorted.collect(Collectors.toList());
    }

    public ClaimsMap(String encoded) {
        this._claims = ClaimsMap.fromJSON(encoded);
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

    public Key getKey(Claim claim, List<KeyUsage> usage) {
        String string = get(claim);
        if (string == null || string.length() == 0) { return null; }
        try {
            return new Key(usage, string, claim);
        } catch (DimeCryptographicException ignored) {
            return null;
        }
    }

    public List<ItemLink> getItemLinks(Claim claim) {
        String string = get(claim);
        if (string == null || string.length() == 0) { return null; }
        try {
            return ItemLink.fromEncodedList(string);
        } catch (DimeFormatException e) {
            return null;
        }
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

    protected final HashMap<String, Object> _claims;

    private static HashMap<String, Object> fromJSON(String json) {
        JSONObject jsonObject = new JSONObject(json);
        return (HashMap<String, Object>)jsonObject.toMap();
    }

}