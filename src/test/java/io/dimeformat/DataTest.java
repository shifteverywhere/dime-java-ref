//
//  DataTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.DimeIntegrityException;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DataTest {

    @Test
    void getItemIdentifierTest1() {
        Data data = new Data(UUID.randomUUID());
        assertEquals("DAT", data.getItemIdentifier());
        assertEquals("DAT", Data.ITEM_IDENTIFIER);
    }

    @Test
    void dataTest1() {
        Instant now = Instant.now();
        Data data = new Data(UUID.randomUUID(), 10, Commons.CONTEXT);
        data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertNotNull(data.getUniqueId());
        assertEquals(Commons.CONTEXT, data.getContext());
        assertEquals(Commons.PAYLOAD, new String(data.getPayload(), StandardCharsets.UTF_8));
        assertTrue(data.getIssuedAt().compareTo(now) >= 0 && data.getIssuedAt().compareTo(now.plusSeconds(1)) <= 0);
        assertTrue(data.getExpiresAt().compareTo(now.plusSeconds(9)) > 0 && data.getExpiresAt().compareTo(now.plusSeconds(11)) < 0);
        assertNull(data.getMIMEType());
    }

    @Test
    void dataTest2() {
        Data data = new Data(UUID.randomUUID(), -1, Commons.CONTEXT);
        data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
        assertEquals(Commons.MIMETYPE, data.getMIMEType());
        assertNull(data.getExpiresAt());
    }

    @Test
    void dataTest3() {
        Data data1 = new Data(UUID.randomUUID());
        Data data2 = new Data(UUID.randomUUID());
        assertNotEquals(data1.getUniqueId(), data2.getUniqueId());
    }

    @Test
    void exportTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Data data = new Data(Commons.getIssuerIdentity().getSubjectId(), 120, Commons.CONTEXT);
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            String encoded = data.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Data.ITEM_IDENTIFIER)));
            assertEquals(3, encoded.split("\\.").length);
            data.sign(Commons.getIssuerKey());
            encoded = data.exportToEncoded();
            assertEquals(4, encoded.split("\\.").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest2() {
        try {
            Data data = new Data(UUID.randomUUID());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            String encoded1 = data.exportToEncoded();
            String encoded2 = data.exportToEncoded();
            assertNotNull(encoded1);
            assertNotNull(encoded2);
            assertEquals(encoded1, encoded2);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() {
        try {
            String exported = "Di/1j:DAT.eyJtaW0iOiJ0ZXh0L3BsYWluIiwiaXNzIjoiNTJlMWYwNTMtN2FmOS00NjE5LTk5MGItZWVjZTk0NjQzMjk1IiwidWlkIjoiN2E1MjQ0ZTMtNDJmMS00MDYzLTlkZWMtZTY2NGQ4ODQzMDdhIiwiZXhwIjoiMjAyMi0wNi0xMVQxMToyNzowOC45ODQyMTBaIiwiaWF0IjoiMjAyMi0wNi0xMVQxMToyNTowOC45ODQyMTBaIiwiY3R4IjoiaW8uZGltZWZvcm1hdC50ZXN0In0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            Data data = Item.importFromEncoded(exported);
            assertNotNull(data);
            assertEquals(UUID.fromString("7a5244e3-42f1-4063-9dec-e664d884307a"), data.getUniqueId());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), data.getIssuerId());
            assertEquals(Commons.MIMETYPE, data.getMIMEType());
            assertEquals(Commons.CONTEXT, data.getContext());
            assertEquals(Commons.PAYLOAD, new String(data.getPayload(), StandardCharsets.UTF_8));
            assertEquals(Instant.parse("2022-06-11T11:25:08.984210Z"), data.getIssuedAt());
            assertEquals(Instant.parse("2022-06-11T11:27:08.984210Z"), data.getExpiresAt());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest2() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Data data1 = new Data(Commons.getIssuerIdentity().getSubjectId(), 120, Commons.CONTEXT);
            data1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            String exported = data1.exportToEncoded();
            Data data2 = Item.importFromEncoded(exported);
            assertNotNull(data2);
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), data2.getIssuerId());
            assertEquals(data1.getIssuedAt(), data2.getIssuedAt());
            assertEquals(data1.getExpiresAt(), data2.getExpiresAt());
            assertEquals(Commons.MIMETYPE, data2.getMIMEType());
            assertEquals(Commons.PAYLOAD, new String(data2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest3() {
        Dime.setTrustedIdentity(Commons.getTrustedIdentity());
        String encoded = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
        try {
            Data data = Item.importFromEncoded(encoded);
            fail("Expected exception not thrown.");
        } catch (ClassCastException e) {
            /* All is well, carry on */
        }
        catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest1() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Data data = new Data(Commons.getIssuerIdentity().getSubjectId());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(Commons.getIssuerKey());
            data.verify(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest2() {
        try {
            Dime.setTrustedIdentity(Commons.getTrustedIdentity());
            Data data = new Data(Commons.getIssuerIdentity().getSubjectId());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(Commons.getIssuerKey());
            data.verify(Commons.getAudienceKey());
        } catch (DimeIntegrityException e) {
            // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Data data = new Data(Commons.getIssuerIdentity().getSubjectId(), context);
        assertEquals(context, data.getContext());
    }

    @Test
    void contextTest2() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Data(Commons.getIssuerIdentity().getSubjectId(), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}
