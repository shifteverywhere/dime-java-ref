//
//  TagTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyType;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class TagTest {

    @Test
    void getItemIdentifierTest1() {
        Tag tag = new Tag();
        assertEquals("TAG", tag.getItemIdentifier());
        assertEquals("TAG", Tag.ITEM_IDENTIFIER);
    }

    @Test
    void tagTest1() {
        Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
        assertEquals(Commons.getIssuerIdentity().getSubjectId(), tag.getIssuerId());
        assertNull(tag.getContext());
        assertNull(tag.getItemLinks());
    }

    @Test
    void tagTest2() {
        Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId(), Commons.CONTEXT);
        assertEquals(Commons.getIssuerIdentity().getSubjectId(), tag.getIssuerId());
        assertEquals(Commons.CONTEXT, tag.getContext());
        assertNull(tag.getItemLinks());
    }

    @Test
    void tagTest3() {
        try {
            Tag tag = new Tag(null);
        } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
    }

    @Test
    void tagTest4() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId(), context);
        } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
    }

    @Test
    void tagTest5() {
        try {
            List<Item> items = List.of(Key.generateKey(KeyType.IDENTITY), Key.generateKey(KeyType.EXCHANGE));
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId(), Commons.CONTEXT, items);
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), tag.getIssuerId());
            assertEquals(Commons.CONTEXT, tag.getContext());
            assertNotNull(tag.getItemLinks());
            assertEquals(2, tag.getItemLinks().size());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest1() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            tag.addItemLink(Key.generateKey(KeyType.IDENTITY));
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Key.ITEM_IDENTIFIER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest2() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            tag.addItemLink(Commons.getIssuerIdentity());
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Identity.ITEM_IDENTIFIER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest3() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            tag.addItemLink(message);
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Message.ITEM_IDENTIFIER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest4() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            tag.addItemLink(Key.generateKey(KeyType.IDENTITY));
            tag.sign(Commons.getIssuerKey());
            tag.addItemLink(Commons.getIssuerIdentity());
            fail("Expected exception not thrown.");
        } catch (IllegalStateException e) {
            /* All is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest5() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            tag.addItemLink(Commons.getTrustedIdentity());
            tag.addItemLink(Commons.getIntermediateIdentity());
            tag.addItemLink(Commons.getIssuerIdentity());
            tag.addItemLink(Commons.getAudienceKey());
            List<ItemLink> links = tag.getItemLinks();
            assertNotNull(links);
            assertEquals(4, links.size());
            ItemLink link0 = links.get(0);
            assertEquals(Commons.getTrustedIdentity().getItemIdentifier(), link0.itemIdentifier);
            assertEquals(Commons.getTrustedIdentity().getUniqueId(), link0.uniqueId);
            assertEquals(Commons.getTrustedIdentity().thumbprint(), link0.thumbprint);
            ItemLink link1 = links.get(1);
            assertEquals(Commons.getIntermediateIdentity().getItemIdentifier(), link1.itemIdentifier);
            assertEquals(Commons.getIntermediateIdentity().getUniqueId(), link1.uniqueId);
            assertEquals(Commons.getIntermediateIdentity().thumbprint(), link1.thumbprint);
            ItemLink link2 = links.get(2);
            assertEquals(Commons.getIssuerIdentity().getItemIdentifier(), link2.itemIdentifier);
            assertEquals(Commons.getIssuerIdentity().getUniqueId(), link2.uniqueId);
            assertEquals(Commons.getIssuerIdentity().thumbprint(), link2.thumbprint);
            ItemLink link3 = links.get(3);
            assertEquals(Commons.getAudienceKey().getItemIdentifier(), link3.itemIdentifier);
            assertEquals(Commons.getAudienceKey().getUniqueId(), link3.uniqueId);
            assertEquals(Commons.getAudienceKey().thumbprint(), link3.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 10);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            tag.addItemLink(message);
            tag.addItemLink(Key.generateKey(KeyType.IDENTITY));
            tag.addItemLink(Commons.getIssuerIdentity());
            tag.sign(Commons.getIssuerKey());
            String encoded = tag.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Tag.ITEM_IDENTIFIER)));
            assertEquals(3, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest2() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getSubjectId());
            tag.addItemLink(Key.generateKey(KeyType.IDENTITY));
            tag.exportToEncoded();
            fail("Expected exception not thrown.");
        } catch (IllegalStateException e) {
            /* All is well */
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di:TAG.eyJpc3MiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJsbmsiOiJNU0cuZTZjZWRlMDEtOTliNC00NGM1LTg2NDEtYzdjZGY5ZGY1MmI2LmU4NTE5N2I2ZTk3Yjg4YjU0MmU2ODJhMmQ5NzgzMjAwOGQyZTczZjg4ZjQ1ZmE2NjJiNmRhOTY4MDM0ZTBiODk6S0VZLjA4YTc0MGYxLTliYzgtNDMwMS1iMzRkLTQyNmYwYWVmMmZmYy5lZjFhNzZiMmY1ZjUyMjRmYTE2NjY5MDQxNWEyODcxYWQ4ZDFhOTY0OTVkMDM1YzExOTc1OWE0ZTZhNmVmMjZiOklELjJhN2Q0MmEzLTZiNDUtNGE0YS1iYjNkLWVjOTRlYzM3OWYxZi5mNTUxNDY2YWE0MDJmYWVkNzBiZmFhYjlmYmJjM2UzNjI0MWRiMzQ5YWNiY2Y3MWM2YmEyOGZiNGY2YzA5MzRjIiwidWlkIjoiNDc5MzE5N2ItZjM3Mi00NzRiLThmNzYtMDViZWMwNmIxNDU4In0.L1apyM3ULPIioUdizKlSyO2O3Z0GzKNzQUKDRpgCvq0pnOZbu+hy/iCX/NkY245/CP/QwJYUeU4MBk9pyPRzDA";
            Tag tag = Item.importFromEncoded(exported);
            assertNotNull(tag);
            assertNotNull(tag.getItemLinks());
            assertEquals(3, tag.getItemLinks().size());
            ItemLink lnk1 = tag.getItemLinks().get(0);
            assertEquals(Message.ITEM_IDENTIFIER, lnk1.itemIdentifier);
            assertEquals("e85197b6e97b88b542e682a2d97832008d2e73f88f45fa662b6da968034e0b89", lnk1.thumbprint);
            assertEquals(UUID.fromString("e6cede01-99b4-44c5-8641-c7cdf9df52b6"), lnk1.uniqueId);
            ItemLink lnk2 = tag.getItemLinks().get(1);
            assertEquals(Key.ITEM_IDENTIFIER, lnk2.itemIdentifier);
            assertEquals("ef1a76b2f5f5224fa166690415a2871ad8d1a96495d035c119759a4e6a6ef26b", lnk2.thumbprint);
            assertEquals(UUID.fromString("08a740f1-9bc8-4301-b34d-426f0aef2ffc"), lnk2.uniqueId);
            ItemLink lnk3 = tag.getItemLinks().get(2);
            assertEquals(Identity.ITEM_IDENTIFIER, lnk3.itemIdentifier);
            assertEquals("f551466aa402faed70bfaab9fbbc3e36241db349acbcf71c6ba28fb4f6c0934c", lnk3.thumbprint);
            assertEquals(UUID.fromString("2a7d42a3-6b45-4a4a-bb3d-ec94ec379f1f"), lnk3.uniqueId);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
