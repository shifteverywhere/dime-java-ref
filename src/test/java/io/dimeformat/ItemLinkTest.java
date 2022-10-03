//
//  ItemLinkTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeFormatException;
import io.dimeformat.exceptions.VerificationException;
import io.dimeformat.enums.KeyCapability;
import org.junit.jupiter.api.Test;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class ItemLinkTest {

    @Test
    void itemLinkTest1() {
        try {
            Key key = Key.generateKey(List.of(KeyCapability.SIGN));
            ItemLink link = new ItemLink(key);
            assertNotNull(link);
            assertEquals(key.getItemIdentifier(), link.itemIdentifier);
            assertEquals(key.thumbprint(), link.thumbprint);
            assertEquals(key.getUniqueId(), link.uniqueId);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void itemLinkTest2() {
        try {
            new ItemLink(null);
            fail("Exception should have been thrown");
        } catch (IllegalArgumentException e) {
            /* All is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void itemLinkTest3() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            ItemLink link = new ItemLink(Key.ITEM_IDENTIFIER, key.thumbprint(), key.getUniqueId());
            assertNotNull(link);
            assertEquals(Key.ITEM_IDENTIFIER, link.itemIdentifier);
            assertEquals(key.thumbprint(), link.thumbprint);
            assertEquals(key.getUniqueId(), link.uniqueId);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void itemLinkTest4() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            try {
                new ItemLink(null, key.thumbprint(), key.getUniqueId());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink("", key.thumbprint(), key.getUniqueId());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.ITEM_IDENTIFIER, null, key.getUniqueId());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.ITEM_IDENTIFIER, "", key.getUniqueId());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.ITEM_IDENTIFIER, key.thumbprint(), null);
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedTest1() {
        try {
            Key key = Commons.getAudienceKey().publicCopy();
            ItemLink link = new ItemLink(key);
            String encoded = link.toEncoded();
            assertNotNull(encoded);
            String compare = key.getItemIdentifier() + "." + key.getUniqueId().toString() + "." + key.thumbprint();
            assertEquals(compare, encoded);
            assertNotEquals(Commons.getAudienceKey().thumbprint(), link.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            ItemLink link = new ItemLink(Commons.getAudienceKey());
            assertTrue(link.verify(Commons.getAudienceKey()));
            assertFalse(link.verify(Commons.getIssuerKey()));
            assertFalse(link.verify(Commons.getAudienceKey().publicCopy()));
            assertFalse(link.verify(null));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyListTest1() {
        try {
            ItemLink link = new ItemLink(Commons.getAudienceKey());
            ItemLink.verify(List.of(Commons.getAudienceKey()), List.of(link));
            try {
                ItemLink.verify(List.of(Commons.getAudienceKey().publicCopy()), List.of(link));
                fail("Exception not thrown.");
            } catch (VerificationException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyListTest2() {
        try {
            List<Item> items = List.of(Commons.getAudienceKey(), Commons.getAudienceIdentity());
            List<Item> revItems = List.of(Commons.getAudienceIdentity(), Commons.getAudienceKey());
            List<ItemLink> links = List.of(new ItemLink(Commons.getAudienceKey()), new ItemLink(Commons.getAudienceIdentity()));
            ItemLink.verify(items, links);
            ItemLink.verify(revItems, links);
            ItemLink.verify(List.of(Commons.getAudienceKey()), links);
            ItemLink.verify(List.of(Commons.getAudienceKey()), links);
            try { ItemLink.verify(null, links); fail("Exception not thrown."); } catch (VerificationException e) { /* all is well */ }
            try { ItemLink.verify(items, null); fail("Exception not thrown."); } catch (VerificationException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedTest2() {
        try {
            Key key = Commons.getAudienceKey().publicCopy();
            ItemLink link = new ItemLink(key.getItemIdentifier(), key.thumbprint(), key.getUniqueId());
            String encoded = link.toEncoded();
            assertNotNull(encoded);
            String compare = key.getItemIdentifier() + "." + key.getUniqueId().toString() + "." + key.thumbprint();
            assertEquals(compare, encoded);
            assertNotEquals(Commons.getAudienceKey().thumbprint(), link.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedListTest1() {
        try {
            List<ItemLink> links = Arrays.asList(new ItemLink(Commons.getAudienceIdentity()), new ItemLink(Commons.getAudienceKey().publicCopy()));
            String encoded = ItemLink.toEncoded(links);
            assertNotNull(encoded);
            assertTrue(encoded.startsWith(Identity.ITEM_IDENTIFIER));
            String[] components = encoded.split("\\" + Dime.SECTION_DELIMITER);
            assertEquals(2, components.length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedListTest2() {
        try {
            List<ItemLink> links = List.of(new ItemLink(Commons.getAudienceIdentity()));
            String encoded = ItemLink.toEncoded(links);
            assertNotNull(encoded);
            assertTrue(encoded.startsWith(Identity.ITEM_IDENTIFIER));
            String[] components = encoded.split("\\" + Dime.SECTION_DELIMITER);
            assertEquals(1, components.length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedListTest3() {
        try {
            assertNull(ItemLink.toEncoded(null));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedTest1() {
        try {
            String encoded = "KEY.c89b08d7-f472-4703-b5d3-3d23fd39e10d.68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc";
            ItemLink link = ItemLink.fromEncoded(encoded);
            assertNotNull(link);
            assertEquals("KEY", link.itemIdentifier);
            assertEquals(UUID.fromString("c89b08d7-f472-4703-b5d3-3d23fd39e10d"), link.uniqueId);
            assertEquals("68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc", link.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedTest2() {
        try {
            ItemLink.fromEncoded(Commons.PAYLOAD);
            fail("Exception should have been thrown");
        } catch (DimeFormatException e) {
            /* All is well, carry on. */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedListTest1() {
        try {
            String lnk1 = new ItemLink(Key.generateKey(KeyCapability.SIGN)).toEncoded();
            String lnk2 = new ItemLink(Key.generateKey(KeyCapability.EXCHANGE)).toEncoded();
            String lnk3 = new ItemLink(Key.generateKey(KeyCapability.EXCHANGE)).toEncoded();
            List<ItemLink> links = ItemLink.fromEncodedList(lnk1 + ":" + lnk2 + ":" + lnk3);
            assertNotNull(links);
            assertEquals(3, links.size());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedListTest2() {
        try {
            ItemLink.fromEncodedList(Commons.PAYLOAD);
            fail("Exception should have been thrown");
        } catch (DimeFormatException e) {
            /* All is well, carry on. */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}