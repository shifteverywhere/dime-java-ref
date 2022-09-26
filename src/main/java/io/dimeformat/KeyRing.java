//
//  KeyRing.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeFormatException;

import java.util.Collection;
import java.util.HashMap;
import java.util.Set;

public class KeyRing {

    /**
     * Returns the number of name-item mappings in this key ring.
     * @return The number of name-item mappings in this key ring.
     */
    public int size() {
       return _keyRing != null ? _keyRing.size() : 0;
    }

    public boolean isEmpty() {
        return _keyRing == null || _keyRing.isEmpty();
    }

    public boolean containsName(String name) {
        return _keyRing != null && _keyRing.containsKey(name);
    }

    public boolean containsItem(Item item) {
        if (item instanceof Key) {
            String name = Dime.crypto.generateKeyIdentifier(((Key) item));
            Key key = (Key) _keyRing.get(name);
            return key.getPublic().equals(((Key) item).getPublic());
        } else if (item instanceof Identity) {
            String name = ((Identity) item).getSubjectId().toString().toLowerCase();
            Identity identity = (Identity) _keyRing.get(name);
            return identity.getSubjectId().compareTo(((Identity) item).getSubjectId()) == 0 &&
                    identity.getPublicKey().getPublic().equals(((Identity) item).getPublicKey().getPublic());
        }
        return false;
    }

    public Item get(String name) {
        return _keyRing != null ? _keyRing.get(name) : null;
    }

    public void put(Key key) {
        put(Dime.crypto.generateKeyIdentifier(key), key);
    }

    public void put(Identity identity) {
        put(identity.getSubjectId().toString().toLowerCase(), identity);
    }

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

    public void importFromEncoded(String encoded) throws DimeFormatException {
        Envelope envelope = Envelope.importFromEncoded(encoded);
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

    public String exportToEncoded() {
        if (_keyRing != null && _keyRing.isEmpty()) {
            Envelope envelope = new Envelope();
            for (String name: nameSet()) {
                envelope.addItem(get(name));
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
