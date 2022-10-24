//
//  KeyRing.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat.keyring;

import io.dimeformat.*;
import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.CryptographyException;
import io.dimeformat.exceptions.InvalidFormatException;
import io.dimeformat.exceptions.IntegrityStateException;

import java.util.Collection;
import java.util.HashMap;
import java.util.Set;
import java.util.UUID;

/**
 * DiME uses a key ring to verify trust. This is done by storing trusted keys and identities in the key ring and then
 * calling {@link Item#verify()} to verify the trust against those keys and identities.
 */
public class KeyRing {

    /**
     * Returns the number of name-item mappings in this key ring.
     * @return The number of name-item mappings in this key ring.
     */
    public int size() {
       return _keyRing != null ? _keyRing.size() : 0;
    }

    /**
     * Indicates if the key ring is empty or not.
     * @return True if it is empty, false otherwise.
     */
    public boolean isEmpty() {
        return _keyRing == null || _keyRing.isEmpty();
    }

    /**
     * Check if an item with the provided name is part of the key ring.
     * @param name The name of the item to check for.
     * @return True if the item is part of the key ring, false otherwise
     */
    public boolean containsName(String name) {
        return _keyRing != null && _keyRing.containsKey(name);
    }

    /**
     * Checks if an item is part of the key ring.
     * @param item The item to check for.
     * @return True if item is part of the key ring, false otherwise.
     */
    public boolean containsItem(Item item) {
        if (_keyRing == null) return false;
        if (item instanceof Key) {
            String name = Dime.crypto.generateKeyName(((Key) item));
            if (_keyRing.containsKey(name)) {
                Key ringKey = (Key) _keyRing.get(name);
                return ringKey.getPublic().equals(((Key) item).getPublic());
            }
        } else if (item instanceof Identity) {
            String name = (item.getClaim(Claim.SUB).toString().toLowerCase());
            if (_keyRing.containsKey(name)) {
                Identity ringIdentity = (Identity) _keyRing.get(name);
                return ((UUID) ringIdentity.getClaim(Claim.SUB)).compareTo(item.getClaim(Claim.SUB)) == 0 &&
                        ringIdentity.getPublicKey().getPublic().equals(((Identity) item).getPublicKey().getPublic());
            }
        }
        return false;
    }

    /**
     * Returns an item from the key ring.
     * @param name The name of the item to return.
     * @return The found item, null if none were found.
     */
    public Item get(String name) {
        return _keyRing != null ? _keyRing.get(name) : null;
    }


    /**
     * Adds a Key or Identity instance to the key ring.
     * @param item The item to add.
     * @return The name associated with the item added.
     */
    public String put(Item item) {
        if (item == null) { throw new IllegalArgumentException("Unable to add item to key ring, item to add must not be null."); }
        String name = KeyRing.itemName(item);
        if (name == null || name.length() == 0) { throw new IllegalArgumentException("Unable to add item to key ring, invalid item."); }
        if (_keyRing == null) {
            _keyRing = new HashMap<>();
        }
        _keyRing.put(name, item);
        return name;
    }

    /**
     * Removes a Key or Identity instance from the key ring.
     * @param item The item to remove.
     * @return True if item was removed, false is it could not be found.
     */
    public boolean remove(Item item) {
        return remove(KeyRing.itemName(item));
    }

    /**
     * Removes an item from the key ring from its associated name.
     * @param name Name of the item to remove.
     * @return True if item was removed, false is it could not be found.
     */
    public boolean remove(String name) {
        if (_keyRing != null && name != null && name.length() > 0) {
            return _keyRing.remove(name) != null;
        }
        return false;
    }

    /**
     * Removes all keys and identities in the key ring. The key ring will be empty after this call returns.
     */
    public void clear() {
        if (_keyRing != null) {
            _keyRing.clear();
        }
    }

    /**
     * Returns a Set view of the names contained in this key ring. The set is backed by the map, so changes to the map
     * are reflected in the set, and vice-versa. If the map is modified while an iteration over the set is in progress
     * (except through the iterator's own remove operation), the results of the iteration are undefined. The set
     * supports element removal, which removes the corresponding mapping from the map, via the Iterator.remove,
     * Set.remove, removeAll, retainAll, and clear operations. It does not support the add or addAll operations.
     * @return A set view of the names contained in this key ring.
     */
    public Set<String> nameSet() {
       return _keyRing != null ? _keyRing.keySet() : null;
    }

    /**
     * Returns a Collection view of the items (keys and identities) contained in this key ring. The collection is backed
     * by the map, so changes to the map are reflected in the collection, and vice-versa. If the map is modified while an
     * iteration over the collection is in progress (except through the iterator's own remove operation), the results of
     * the iteration are undefined. The collection supports element removal, which removes the corresponding mapping from
     * the map, via the Iterator.remove, Collection.remove, removeAll, retainAll and clear operations. It does not
     * support the add or addAll operations.
     * @return A view of the key and identities contained in this key ring.
     */
    public Collection<Item> items() {
        return _keyRing != null ? _keyRing.values() : null;
    }

    /**
     *  Imports all items in a DiME encoded envelope string to the key ring. If a verification key is provided then the
     *  signature of the envelope is first verified before any items are imported.
     * @param encoded The DiME encoded string with items that should be imported.
     * @param verifyKey A key to verify the signature of the DiME encoded string, may be null to skip the verification.
     * @throws InvalidFormatException If something is wrong with the encoded string.
     * @throws IntegrityStateException If the verification of the signature fails.
     */
    public void importFromEncoded(String encoded, Key verifyKey) throws InvalidFormatException, IntegrityStateException {
        Envelope envelope = Envelope.importFromEncoded(encoded);
        if (verifyKey != null) {
            IntegrityState state = envelope.verify(verifyKey);
            if (!state.isValid()) {
                throw new IntegrityStateException(state, "Unable to import key ring, unable to verify integrity.");
            }
        }
        for (Item item: envelope.getItems()) {
            if (item instanceof Key) {
                put((Key) item);
            } else if (item instanceof Identity) {
                put((Identity) item);
            } else {
                throw new IllegalArgumentException("Unable to import key ring, encoded envelope must only contain keys and identities.");
            }
        }
    }


    /**
     * Returns a DiME encoded string of all items stored in the key ring. If a signing key is included then the returned
     * DiME envelope will be signed by this key.
     * @param signingKey A key to sign the generated DiME envelope, may be null.
     * @return A DiME encoded string, null if the key ring is empty.
     * @throws CryptographyException If something goes wrong while signing the generated envelope.
     */
    public String exportToEncoded(Key signingKey) throws CryptographyException {
        if (isEmpty()) { return null; }
        Envelope envelope = new Envelope();
        for (String name: nameSet()) {
            envelope.addItem(get(name));
        }
        if (signingKey != null) {
            envelope.sign(signingKey);
        }
        return envelope.exportToEncoded();
    }

    public IntegrityState verify(Item item) {
        if (size() == 0) {
            return IntegrityState.FAILED_NO_KEY_RING;
        }
        IntegrityState state = IntegrityState.FAILED_NOT_TRUSTED;
        for (Item trustedItem: items()) {
            state = trustedItem.verifyDates();
            if (!state.isValid()) {
                return state;
            }
            Key trustedKey = getKey(trustedItem);
            if (trustedKey == null) {
                return IntegrityState.FAILED_INTERNAL_FAULT;
            }
            state = item.verifySignature(trustedKey);
            if (state != IntegrityState.FAILED_KEY_MISMATCH) {
                return state;
            }
        }
        return state;
    }

    /// PRIVATE ///

    private HashMap<String, Item> _keyRing;

    private static String itemName(Item item) {
        String name = null;
        if (item instanceof Key) {
            name = Dime.crypto.generateKeyName((Key) item);
        } else if (item instanceof Identity) {
            name = item.getClaim(Claim.SUB).toString().toLowerCase();
        }
        return name;
    }

    private static Key getKey(Item item) {
        if (item instanceof Key) {
            return (Key) item;
        } else if (item instanceof Identity) {
            return ((Identity) item).getPublicKey();
        }
        return null;
    }

}
