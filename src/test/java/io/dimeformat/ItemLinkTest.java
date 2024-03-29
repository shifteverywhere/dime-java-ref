//
//  ItemLinkTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.exceptions.InvalidFormatException;
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
            ItemLink link = new ItemLink(key, Dime.crypto.getDefaultSuiteName());
            assertNotNull(link);
            assertEquals(key.getHeader(), link.itemIdentifier);
            assertEquals(key.generateThumbprint(), link.thumbprint);
            assertEquals(key.getClaim(Claim.UID), link.uniqueId);
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
            ItemLink link = new ItemLink(Key.HEADER, key.generateThumbprint(), key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
            assertNotNull(link);
            assertEquals(Key.HEADER, link.itemIdentifier);
            assertEquals(key.generateThumbprint(), link.thumbprint);
            assertEquals(key.getClaim(Claim.UID), link.uniqueId);
            assertEquals(Dime.crypto.getDefaultSuiteName(), link.cryptoSuiteName);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void itemLinkTest4() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            try {
                new ItemLink(null, key.generateThumbprint(), key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink("", key.generateThumbprint(), key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.HEADER, null, key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.HEADER, "", key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.HEADER, key.generateThumbprint(), null, Dime.crypto.getDefaultSuiteName());
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.HEADER, key.generateThumbprint(), key.getClaim(Claim.UID),null);
                fail("Exception should have been thrown");
            } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
            try {
                new ItemLink(Key.HEADER, key.generateThumbprint(), key.getClaim(Claim.UID),"");
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
            String compare = key.getHeader() + "." + key.getClaim(Claim.UID).toString() + "." + key.generateThumbprint() + "." + Dime.crypto.getDefaultSuiteName();
            assertEquals(compare, encoded);
            assertNotEquals(Commons.getAudienceKey().generateThumbprint(), link.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedTest2() {
        try {
            Key key = Commons.getAudienceKey().publicCopy();
            ItemLink link = new ItemLink(key.getHeader(), key.generateThumbprint(), key.getClaim(Claim.UID), Dime.crypto.getDefaultSuiteName());
            String encoded = link.toEncoded();
            assertNotNull(encoded);
            String compare = key.getHeader() + "." + key.getClaim(Claim.UID).toString() + "." + key.generateThumbprint() + "." + Dime.crypto.getDefaultSuiteName();
            assertEquals(compare, encoded);
            assertNotEquals(Commons.getAudienceKey().generateThumbprint(), link.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void toEncodedTest3() {
        try {
            Key key = Key.generateKey(KeyCapability.SIGN);
            ItemLink link = new ItemLink(key, "STN");
            String encoded = link.toEncoded();
            assertNotNull(encoded);
            String compare = key.getHeader() + "." + key.getClaim(Claim.UID).toString() + "." + key.generateThumbprint();
            assertEquals(compare, encoded);
            assertEquals("STN", link.cryptoSuiteName);
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
    void verifyTest2() {
        Key key = Key.generateKey(KeyCapability.SIGN);
        assertEquals(Dime.crypto.getDefaultSuiteName(), key.getCryptoSuiteName());
        ItemLink link = new ItemLink(key, "STN");
        assertTrue(link.verify(key));
        assertEquals("STN", link.cryptoSuiteName);
    }

    @Test
    void verifyListTest1() {
        try {
            ItemLink link = new ItemLink(Commons.getAudienceKey());
            assertTrue(ItemLink.verify(List.of(Commons.getAudienceKey()), List.of(link)).isValid());
            assertFalse(ItemLink.verify(List.of(Commons.getAudienceKey().publicCopy()), List.of(link)).isValid());
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
            assertTrue(ItemLink.verify(items, links).isValid());
            assertTrue(ItemLink.verify(revItems, links).isValid());
            assertTrue(ItemLink.verify(List.of(Commons.getAudienceKey()), links).isValid());
            assertTrue(ItemLink.verify(List.of(Commons.getAudienceKey()), links).isValid());
            try { ItemLink.verify(null, links); fail("Exception not thrown."); } catch (NullPointerException e) { /* all is well */ }
            try { ItemLink.verify(items, null); fail("Exception not thrown."); } catch (NullPointerException e) { /* all is well */ }
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
            assertTrue(encoded.startsWith(Identity.HEADER));
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
            assertTrue(encoded.startsWith(Identity.HEADER));
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
            assertEquals("STN", link.cryptoSuiteName);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedTest2() {
        try {
            String encoded = "KEY.c89b08d7-f472-4703-b5d3-3d23fd39e10d.68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc.DSC";
            ItemLink link = ItemLink.fromEncoded(encoded);
            assertNotNull(link);
            assertEquals("KEY", link.itemIdentifier);
            assertEquals(UUID.fromString("c89b08d7-f472-4703-b5d3-3d23fd39e10d"), link.uniqueId);
            assertEquals("68cd898db0b2535c912f6aa5f565306991ba74760b2955e7fb8dc91fd45276bc", link.thumbprint);
            assertEquals("DSC", link.cryptoSuiteName);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void fromEncodedTest3() {
        try {
            ItemLink.fromEncoded(Commons.PAYLOAD);
            fail("Exception should have been thrown");
        } catch (InvalidFormatException e) {
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
        } catch (InvalidFormatException e) {
            /* All is well, carry on. */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}