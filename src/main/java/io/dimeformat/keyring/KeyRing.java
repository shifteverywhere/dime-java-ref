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
import io.dimeformat.exceptions.DimeCryptographicException;
import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.VerificationException;

import java.util.Collection;
import java.util.HashMap;
import java.util.Set;

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
        if (item instanceof Key) {
            String name = Dime.crypto.generateKeyName(((Key) item));
            if (_keyRing.containsKey(name)) {
                Key key = (Key) _keyRing.get(name);
                return key.getPublic().equals(((Key) item).getPublic());
            }
        } else if (item instanceof Identity) {
            String name = ((Identity) item).getSubjectId().toString().toLowerCase();
            if (_keyRing.containsKey(name)) {
                Identity identity = (Identity) _keyRing.get(name);
                return identity.getSubjectId().compareTo(((Identity) item).getSubjectId()) == 0 &&
                        identity.getPublicKey().getPublic().equals(((Identity) item).getPublicKey().getPublic());
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
     * Adds a key to the key ring.
     * @param key The key to add.
     */
    public void put(Key key) {
        put(Dime.crypto.generateKeyName(key), key);
    }

    /**
     * Adds an identity to the key ring.
     * @param identity The identity to add.
     */
    public void put(Identity identity) {
        put(identity.getSubjectId().toString().toLowerCase(), identity);
    }

    /**
     * Removes a key from the key ring.
     * @param key The key to remove.
     * @return Returns the removed key, null if none were found.
     */
    public Key remove(Key key) {
        String name = Dime.crypto.generateKeyName(key);
        return (Key) remove(name);
    }

    /**
     * Removes an identity from the key ring.
     * @param identity The identity to remove.
     * @return Returns the removed identity, null if none were found.
     */
    public Identity remove(Identity identity) {
        return (Identity) remove(identity.getSubjectId().toString().toLowerCase());
    }

    /**
     * Removes an item from the key ring.
     * @param name Name of the item to remove.
     * @return Returns the removed item, null if none were found.
     */
    public Item remove(String name) {
        return _keyRing != null ? _keyRing.remove(name) : null;
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
     * @throws DimeFormatException If something is wrong with the encoded string.
     * @throws VerificationException If the verification of the signature fails.
     */
    public void importFromEncoded(String encoded, Key verifyKey) throws DimeFormatException, VerificationException {
        Envelope envelope = Envelope.importFromEncoded(encoded);
        if (verifyKey != null) {
            envelope.verify(verifyKey);
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
     * @throws DimeCryptographicException If something goes wrong while signing the generated envelope.
     */
    public String exportToEncoded(Key signingKey) throws DimeCryptographicException {
        if (_keyRing != null && !_keyRing.isEmpty()) {
            Envelope envelope = new Envelope();
            for (String name: nameSet()) {
                envelope.addItem(get(name));
            }
            if (signingKey != null) {
                envelope.sign(signingKey);
            }
            return envelope.exportToEncoded();
        }
        return null;
    }

    /// PRIVATE ///

    private HashMap<String, Item> _keyRing;

    private void put(String name, Item item) {
        if (name == null || name.length() == 0) { throw new IllegalArgumentException("Unable to add to key ring, name must not be null or empty."); }
        if (item == null) { throw new IllegalArgumentException("Unable to add to key ring, item to add must not be null."); }
        if (item instanceof Key || item instanceof Identity) {
            if (_keyRing == null) {
                _keyRing = new HashMap<String, Item>();
            }
            _keyRing.put(name, item);
            return;
        }
        throw new IllegalArgumentException("Unable to add to key ring, item to add must either be an instance of Key or Identity.");
    }


}
