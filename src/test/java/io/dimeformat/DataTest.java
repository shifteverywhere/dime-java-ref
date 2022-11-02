//
//  DataTest.java
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class DataTest {

    @Test
    void getHeaderTest1() {
        Data data = new Data(UUID.randomUUID());
        assertEquals("DAT", data.getHeader());
        assertEquals("DAT", Data.HEADER);
    }

    @Test
    void dataTest1() {
        Instant now = Instant.now();
        Data data = new Data(UUID.randomUUID(), 10L, Commons.CONTEXT);
        data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        assertNotNull(data.getClaim(Claim.UID));
        assertEquals(Commons.CONTEXT, data.getClaim(Claim.CTX));
        assertEquals(Commons.PAYLOAD, new String(data.getPayload(), StandardCharsets.UTF_8));
        assertTrue(((Instant) data.getClaim(Claim.IAT)).compareTo(now) >= 0 && ((Instant) data.getClaim(Claim.IAT)).compareTo(now.plusSeconds(1)) <= 0);
        assertTrue(((Instant) data.getClaim(Claim.EXP)).compareTo(now.plusSeconds(9)) > 0 && ((Instant) data.getClaim(Claim.EXP)).compareTo(now.plusSeconds(11)) < 0);
        assertNull(data.getClaim(Claim.MIM));
    }

    @Test
    void dataTest2() {
        Data data = new Data(UUID.randomUUID(), Dime.NO_EXPIRATION, Commons.CONTEXT);
        data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
        assertEquals(Commons.MIMETYPE, data.getClaim(Claim.MIM));
        assertNull(data.getClaim(Claim.EXP));
    }

    @Test
    void dataTest3() {
        Data data1 = new Data(UUID.randomUUID());
        Data data2 = new Data(UUID.randomUUID());
        assertNotEquals((UUID) data1.getClaim(Claim.UID), data2.getClaim(Claim.UID));
    }

    @Test
    void claimTest1() {
        Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        assertNotNull(data.getClaim(Claim.ISS));
        assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), data.getClaim(Claim.ISS));
    }

    @Test
    void claimTest2() {
        Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
        data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
        assertNotNull(data.getClaim(Claim.MIM));
        assertEquals(Commons.MIMETYPE, data.getClaim(Claim.MIM));
        data.removeClaim(Claim.MIM);
        assertNull(data.getClaim(Claim.MIM));
    }

    @Test
    void claimTest3() {
        try {
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.putClaim(Claim.AMB, new String[] { "one", "two" });
            assertNotNull(data.getClaim(Claim.AMB));
            data.putClaim(Claim.AUD, UUID.randomUUID());
            assertNotNull(data.getClaim(Claim.AUD));
            data.putClaim(Claim.CTX, Commons.CONTEXT);
            assertNotNull(data.getClaim(Claim.CTX));
            data.putClaim(Claim.EXP, Instant.now());
            assertNotNull(data.getClaim(Claim.EXP));
            data.putClaim(Claim.IAT, Instant.now());
            assertNotNull(data.getClaim(Claim.IAT));
            data.putClaim(Claim.ISS, UUID.randomUUID());
            assertNotNull(data.getClaim(Claim.ISS));
            data.putClaim(Claim.ISU, Commons.ISSUER_URL);
            assertNotNull(data.getClaim(Claim.ISU));
            data.putClaim(Claim.KID, UUID.randomUUID());
            assertNotNull(data.getClaim(Claim.KID));
            data.putClaim(Claim.MIM, Commons.MIMETYPE);
            assertNotNull(data.getClaim(Claim.MIM));
            data.putClaim(Claim.MTD, new String[] { "abc", "def" });
            assertNotNull(data.getClaim(Claim.MTD));
            data.putClaim(Claim.SUB, UUID.randomUUID());
            assertNotNull(data.getClaim(Claim.SUB));
            data.putClaim(Claim.SYS, Commons.SYSTEM_NAME);
            assertNotNull(data.getClaim(Claim.SYS));
            data.putClaim(Claim.UID, UUID.randomUUID());
            assertNotNull(data.getClaim(Claim.UID));
            try { data.putClaim(Claim.CAP, List.of(KeyCapability.ENCRYPT)); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { data.putClaim(Claim.KEY,Commons.getIssuerKey().getSecret()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { data.putClaim(Claim.LNK, new ItemLink(Commons.getIssuerKey(), Dime.crypto.getDefaultSuiteName())); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { Map<String, Object> pri = new HashMap<>(); pri.put("tag", Commons.PAYLOAD); data.putClaim(Claim.PRI, pri); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
            try { data.putClaim(Claim.PUB, Commons.getIssuerKey().getPublic()); fail("Exception not thrown."); } catch (IllegalArgumentException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest4() {
        try {
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(Commons.getIssuerKey());
            try { data.removeClaim(Claim.ISS); fail("Exception not thrown."); } catch (IllegalStateException e) { /* all is well */ }
            try { data.putClaim(Claim.EXP, Instant.now()); } catch (IllegalStateException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void claimTest5() {
        try {
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(Commons.getIssuerKey());
            data.strip();
            data.removeClaim(Claim.ISS);
            data.putClaim(Claim.IAT, Instant.now());
        } catch (Exception e) {
            fail("Unexpected exception thrown:" + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Commons.initializeKeyRing();
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE, Commons.CONTEXT);
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            String encoded = data.exportToEncoded();
            assertNotNull(encoded);
            assertTrue(encoded.length() > 0);
            assertTrue(encoded.startsWith(Commons.fullHeaderFor(Data.HEADER)));
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
            String exported = "Di:DAT.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTEwLTI0VDIyOjA3OjQ0Ljk4MzM0OVoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA2OjQ0Ljk4MzM0OVoiLCJpc3MiOiI1NzE4OTg0MC0yMGFhLTRlZWEtOTg3OC1iOTIzYTc3ZmIyZWIiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiYjRlNDE5NmItMDkzYS00ZTc5LTg1ZWEtZWMxMWQ5MTMxYzA4In0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            Data data = Item.importFromEncoded(exported);
            assertNotNull(data);
            assertEquals(UUID.fromString("b4e4196b-093a-4e79-85ea-ec11d9131c08"), data.getClaim(Claim.UID));
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB), data.getClaim(Claim.ISS));
            assertEquals(Commons.MIMETYPE, data.getClaim(Claim.MIM));
            assertEquals(Commons.CONTEXT, data.getClaim(Claim.CTX));
            assertEquals(Commons.PAYLOAD, new String(data.getPayload(), StandardCharsets.UTF_8));
            assertEquals(Instant.parse("2022-10-24T22:06:44.983349Z"), data.getClaim(Claim.IAT));
            assertEquals(Instant.parse("2022-10-24T22:07:44.983349Z"), data.getClaim(Claim.EXP));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest2() {
        try {
            Commons.initializeKeyRing();
            Data data1 = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB), Dime.VALID_FOR_1_MINUTE, Commons.CONTEXT);
            data1.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            String exported = data1.exportToEncoded();
            Data data2 = Item.importFromEncoded(exported);
            assertNotNull(data2);
            assertEquals((UUID) Commons.getIssuerIdentity().getClaim(Claim.SUB),data2.getClaim(Claim.ISS));
            assertEquals((Instant) data1.getClaim(Claim.IAT), data2.getClaim(Claim.IAT));
            assertEquals((Instant) data1.getClaim(Claim.EXP), data2.getClaim(Claim.EXP));
            assertEquals(Commons.MIMETYPE, data2.getClaim(Claim.MIM));
            assertEquals(Commons.PAYLOAD, new String(data2.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest3() {
        Commons.initializeKeyRing();
        String encoded = "Di:KEY.eyJ1aWQiOiIzZjAwY2QxMy00NDc0LTRjMDQtOWI2Yi03MzgzZDQ5MGYxN2YiLCJwdWIiOiJTMjFUWlNMMXV2RjVtVFdLaW9tUUtOaG1rY1lQdzVYWjFWQmZiU1BxbXlxRzVHYU5DVUdCN1BqMTlXU2h1SnVMa2hSRUVKNGtMVGhlaHFSa2FkSkxTVEFrTDlEdHlobUx4R2ZuIiwiaWF0IjoiMjAyMS0xMS0xOFQwODo0ODoyNS4xMzc5MThaIiwia2V5IjoiUzIxVGtnb3p4aHprNXR0RmdIaGdleTZ0MTQxOVdDTVVVTTk4WmhuaVZBamZUNGluaVVrbmZVck5xZlBxZEx1YTJTdnhGZjhTWGtIUzFQVEJDcmRrWVhONnFURW03TXdhMkxSZCJ9";
        try {
            Data item = Item.importFromEncoded(encoded);
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
            Commons.initializeKeyRing();
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
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
            Commons.initializeKeyRing();
            Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB));
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(Commons.getIssuerKey());
            assertFalse(data.verify(Commons.getAudienceKey()).isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Data data = new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
        assertEquals(context, data.getClaim(Claim.CTX));
    }

    @Test
    void contextTest2() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Data(Commons.getIssuerIdentity().getClaim(Claim.SUB), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

}
