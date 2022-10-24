//
//  TagTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.KeyCapability;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class TagTest {

    @Test
    void getHeaderTest1() {
        Tag tag = new Tag();
        assertEquals("TAG", tag.getHeader());
        assertEquals("TAG", Tag.HEADER);
    }

    @Test
    void claimTest1() {
        Tag tag = new Tag();
        assertNull(tag.getClaim(Claim.ISS));
        tag.putClaim(Claim.ISS, Commons.getAudienceIdentity().getClaim(Claim.SUB));
        assertEquals((UUID) Commons.getAudienceIdentity().getClaim(Claim.SUB), tag.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        assertNotNull(tag.getClaim(Claim.ISS));
        tag.removeClaim(Claim.ISS);
        assertNull(tag.getClaim(Claim.ISS));
    }

    @Test
    void claimTest3() {
        try {
            Tag tag = new Tag();
            tag.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(tag.getClaim(Claim.AMB));
            tag.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(tag.getClaim(Claim.AUD));
            tag.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(tag.getClaim(Claim.CTX));
            tag.putClaim(Claim.EXP, Instant.now());
            assertNotNull(tag.getClaim(Claim.EXP));
            tag.putClaim(Claim.IAT, Instant.now());
            assertNotNull(tag.getClaim(Claim.IAT));
            tag.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(tag.getClaim(Claim.ISS));
            tag.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(tag.getClaim(Claim.KID));
            tag.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(tag.getClaim(Claim.MTD));
            tag.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(tag.getClaim(Claim.SUB));
            tag.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(tag.getClaim(Claim.SYS));
            tag.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(tag.getClaim(Claim.UID));
            try { tag.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { tag.putClaim(Claim.KEY, Commons.getIssuerKey().getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { tag.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { tag.putClaim(Claim.MIM, Commons.MIMETYPE); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); tag.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { tag.putClaim(Claim.PUB,  Commons.getIssuerKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            List<Item> items = List.of(Key.generateKey(KeyCapability.SIGN), Key.generateKey(KeyCapability.EXCHANGE));
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT, items);
            tag.sign(Commons.getIssuerKey());
            try { tag.removeClaim(Claim.CTX); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { tag.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            List<Item> items = List.of(Key.generateKey(KeyCapability.SIGN), Key.generateKey(KeyCapability.EXCHANGE));
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT, items);
            tag.sign(Commons.getIssuerKey());
            tag.strip();
            tag.removeClaim(Claim.CTX);
            tag.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void tagTest1() {
        Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), tag.getClaim(Claim.ISS));
        assertNull(tag.getClaim(Claim.CTX));
        assertNull(tag.getItemLinks());
    }

    @Test
    void tagTest2() {
        Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT);
        assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), tag.getClaim(Claim.ISS));
        assertEquals(Commons.CONTEXT, tag.getClaim(Claim.CTX));
        assertNull(tag.getItemLinks());
    }

    @Test
    void tagTest3() {
        try {
            new Tag(null);
        } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
    }

    @Test
    void tagTest4() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
        } catch (IllegalArgumentException e) { /* All is well, carry on. */ }
    }

    @Test
    void tagTest5() {
        try {
            List<Item> items = List.of(Key.generateKey(KeyCapability.SIGN), Key.generateKey(KeyCapability.EXCHANGE));
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT, items);
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), tag.getClaim(Claim.ISS));
            assertEquals(Commons.CONTEXT, tag.getClaim(Claim.CTX));
            assertNotNull(tag.getItemLinks());
            assertEquals(2, tag.getItemLinks().size());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void tagTest6() {
        try {
            List<Item> items = List.of(Key.generateKey(KeyCapability.SIGN), Key.generateKey(KeyCapability.EXCHANGE));
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB), items);
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), tag.getClaim(Claim.ISS));
            assertNull(tag.getClaim(Claim.CTX));
            assertEquals(2, tag.getItemLinks().size());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest1() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            tag.addItemLink(Key.generateKey(KeyCapability.SIGN));
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Key.HEADER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest2() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            tag.addItemLink(Commons.getIssuerIdentity());
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Identity.HEADER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest3() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            tag.addItemLink(message);
            assertNotNull(tag.getItemLinks());
            assertEquals(1, tag.getItemLinks().size());
            assertEquals(Message.HEADER, tag.getItemLinks().get(0).itemIdentifier);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void addItemLinkTest4() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            tag.addItemLink(Key.generateKey(KeyCapability.SIGN));
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
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            tag.addItemLink(Commons.getTrustedIdentity());
            tag.addItemLink(Commons.getIntermediateIdentity());
            tag.addItemLink(Commons.getIssuerIdentity());
            tag.addItemLink(Commons.getAudienceKey());
            List<ItemLink> links = tag.getItemLinks();
            assertNotNull(links);
            assertEquals(4, links.size());
            ItemLink link0 = links.get(0);
            assertEquals(Commons.getTrustedIdentity().getHeader(), link0.itemIdentifier);
            assertEquals(Commons.getTrustedIdentity().getClaim(Claim.UID), link0.uniqueId);
            assertEquals(Commons.getTrustedIdentity().generateThumbprint(), link0.thumbprint);
            ItemLink link1 = links.get(1);
            assertEquals(Commons.getIntermediateIdentity().getHeader(), link1.itemIdentifier);
            assertEquals(Commons.getIntermediateIdentity().getClaim(Claim.UID), link1.uniqueId);
            assertEquals(Commons.getIntermediateIdentity().generateThumbprint(), link1.thumbprint);
            ItemLink link2 = links.get(2);
            assertEquals(Commons.getIssuerIdentity().getHeader(), link2.itemIdentifier);
            assertEquals(Commons.getIssuerIdentity().getClaim(Claim.UID), link2.uniqueId);
            assertEquals(Commons.getIssuerIdentity().generateThumbprint(), link2.thumbprint);
            ItemLink link3 = links.get(3);
            assertEquals(Commons.getAudienceKey().getHeader(), link3.itemIdentifier);
            assertEquals(Commons.getAudienceKey().getClaim(Claim.UID), link3.uniqueId);
            assertEquals(Commons.getAudienceKey().generateThumbprint(), link3.thumbprint);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB), Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            tag.addItemLink(message);
            tag.addItemLink(Key.generateKey(KeyCapability.SIGN));
            tag.addItemLink(Commons.getIssuerIdentity());
            tag.sign(Commons.getIssuerKey());
            String encoded = tag.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Tag.HEADER)));
            assertEquals(3, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest2() {
        try {
            Tag tag = new Tag(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            tag.addItemLink(Key.generateKey(KeyCapability.SIGN));
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
            assertEquals(Message.HEADER, lnk1.itemIdentifier);
            assertEquals("e85197b6e97b88b542e682a2d97832008d2e73f88f45fa662b6da968034e0b89", lnk1.thumbprint);
            assertEquals(UUID.fromString("e6cede01-99b4-44c5-8641-c7cdf9df52b6"), lnk1.uniqueId);
            ItemLink lnk2 = tag.getItemLinks().get(1);
            assertEquals(Key.HEADER, lnk2.itemIdentifier);
            assertEquals("ef1a76b2f5f5224fa166690415a2871ad8d1a96495d035c119759a4e6a6ef26b", lnk2.thumbprint);
            assertEquals(UUID.fromString("08a740f1-9bc8-4301-b34d-426f0aef2ffc"), lnk2.uniqueId);
            ItemLink lnk3 = tag.getItemLinks().get(2);
            assertEquals(Identity.HEADER, lnk3.itemIdentifier);
            assertEquals("f551466aa402faed70bfaab9fbbc3e36241db349acbcf71c6ba28fb4f6c0934c", lnk3.thumbprint);
            assertEquals(UUID.fromString("2a7d42a3-6b45-4a4a-bb3d-ec94ec379f1f"), lnk3.uniqueId);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
