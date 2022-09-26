//
//  CryptoTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.exceptions.VerificationException;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyType;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeTest {

    @Test
    void getItemTest1() {
        try {
            Message message = new Message(UUID.randomUUID(), UUID.randomUUID(), -1, "message-context");
            Key key = Key.generateKey(List.of(Key.Use.SIGN), "key-context");
            Envelope envelope = new Envelope();
            envelope.addItem(message);
            envelope.addItem(key);
            // Context
            Item item1 = envelope.getItem("key-context");
            assertTrue(item1 instanceof Key);
            assertEquals("key-context", item1.getContext());
            Item item2 = envelope.getItem("message-context");
            assertTrue(item2 instanceof Message);
            assertEquals("message-context", item2.getContext());
            // Unique ID
            Item item3 = envelope.getItem(key.getUniqueId());
            assertTrue(item3 instanceof Key);
            assertEquals(key.getUniqueId(), item3.getUniqueId());
            Item item4 = envelope.getItem(message.getUniqueId());
            assertTrue(item4 instanceof Message);
            assertEquals(message.getUniqueId(), item4.getUniqueId());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest2() {
        try {
            String exported = "Di:MSG.eyJpc3MiOiJkMThhM2ExYi05Y2I2LTQ4MGEtYTJlZC05NGU2NzMwZTVlMzQiLCJ1aWQiOiIwYTQ2YWVkNy0yYzkyLTQwNDQtYmMyMC0yMTc0Y2IwNjA0MmQiLCJhdWQiOiI3YTAyMzkzZS1kMTVkLTQ3NDYtOTU0Mi1hZDljYmUwNzUxYzgiLCJpYXQiOiIyMDIyLTA1LTMwVDE3OjI1OjMxLjQ0NjkxNloiLCJjdHgiOiJtZXNzYWdlLWNvbnRleHQifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.EBiQVW1sKZgKXEg0qDNoxXGUZXhvO8NfxMWn9YL8zhkVU7jp3q2a8p+5dzlRW1AJXwVdk7iH1jhJMux0DGbpBg:KEY.eyJ1aWQiOiIxMWYxNzllZi0yOWIwLTRlZjAtYjA0Yi0xZjU3MTk5ZTJjZjQiLCJwdWIiOiJTVE4rMk5taUIxdlVQSFNDMnplbzZZZzlEQlNTNFdYU3dFSDNLclUxelRCamg4dlV0S3h4WUQiLCJpYXQiOiIyMDIyLTA1LTMwVDE3OjI1OjMxLjcyNzcwNFoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJrZXktY29udGV4dCIsImtleSI6IlNUTithRFp0c2FIaW9nb1R1OW1YdTZqWmJjTG94alE4aFpQaDJ4Rm5SUXhidlRLb1R3YkFLdGFldWRBRFA0dk1US25uRHNtYUcyc3RxeGZaM2hGNXdtWDMzV2V6UFRINFkifQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            // Context
            Item item1 = envelope.getItem("key-context");
            assertTrue(item1 instanceof Key);
            assertEquals("key-context", item1.getContext());
            Item item2 = envelope.getItem("message-context");
            assertTrue(item2 instanceof Message);
            assertEquals("message-context", item2.getContext());
            // Unique ID
            UUID uid1 = UUID.fromString("11f179ef-29b0-4ef0-b04b-1f57199e2cf4");
            Item item3 = envelope.getItem(uid1);
            assertTrue(item3 instanceof Key);
            assertEquals(uid1, item3.getUniqueId());
            UUID uid2 = UUID.fromString("0a46aed7-2c92-4044-bc20-2174cb06042d");
            Item item4 = envelope.getItem(uid2);
            assertTrue(item4 instanceof Message);
            assertEquals(uid2, item4.getUniqueId());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void getItemTest3() {
        Envelope envelope = new Envelope();
        envelope.addItem(Key.generateKey(List.of(Key.Use.SIGN)));
        assertNull(envelope.getItem((String)null));
        assertNull(envelope.getItem(""));
        assertNull(envelope.getItem("invalid-context"));
        assertNull(envelope.getItem((UUID)null));
        assertNull(envelope.getItem(UUID.randomUUID()));
    }

    @Test
    void signTest1() {
        Envelope envelope = new Envelope();
        try {
            envelope.sign(Commons.getIssuerKey());
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
        fail("Should not happen.");
    }

    @Test
    void signTest2() {
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
        try {
            envelope.sign(Commons.getIssuerKey());
        } catch (IllegalStateException e) { 
            return; // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
        fail("Should not happen.");
    }

    @Test
    void signTest3() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        } 
    }

    @Test
    void contextTest1() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
        assertEquals(context, envelope.getContext());
    }

    @Test
    void contextTest2() {
        try {
            String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope1.addItem(message);
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(context, envelope2.getContext());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void contextTest3() {
        String context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            new Envelope(Commons.getIssuerIdentity().getSubjectId(), context);
        } catch (IllegalArgumentException e) { return; } // All is well
        fail("Should not happen.");
    }

    @Test
    void thumbprintTest1() {
        try {
            Envelope envelope = new Envelope();
            envelope.addItem(Commons.getIssuerKey());
            assertNotNull(envelope.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest2(){
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            assertNotNull(envelope.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest3() {
        try {
            Envelope envelope1 = new Envelope();
            envelope1.addItem(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(envelope1.thumbprint(), envelope2.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest4() {
        try {
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope1.addItem(Commons.getIssuerKey());
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();
            Envelope envelope2 = Envelope.importFromEncoded(exported);
            assertEquals(envelope1.thumbprint(), envelope2.thumbprint());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest5() {
        try {
            Envelope envelope = new Envelope();
            envelope.addItem(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertEquals(envelope.thumbprint(), Envelope.thumbprint(exported));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void thumbprintTest6() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertEquals(envelope.thumbprint(), Envelope.thumbprint(exported));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void iirExportTest1() {
        try {
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyType.IDENTITY));
            Envelope envelope = new Envelope();
            envelope.addItem(iir);
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(2, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    public void iirImportTest1() {
        try {
            String exported = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjI1OjIzLjQ1NTEwMFoiLCJwdWIiOiJTVE4uWVptcHlUdGpnWGdXYndBZmRNdmtUMXVGeUVVNG5qVVdQalFTaW1kU1NTQVZldlVHcSIsInVpZCI6IjM4YjYzNDY3LTU5YjUtNDc0ZC1hMGZiLTZjMWRiYjEyNWQ0NSJ9.YjAwNGE0NzdiYzUyN2JjYi4zYzBjOTk0MzEyYzAxZDM5ZTBlM2Q4YTA3NDRjODE1YmZiYjBhZjg5YTRhNWQ0ODZiODVmNGFhODM1YjA0Mzg4NzEyYjU5MWIyYzRjNGIyZWY4MWRiNTZiMzM0MzhiOGMwOTgzZDdmNDFmMmU3ZDAyNDQwMjFkNGUwZThjMzkwZg";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getIssuerId());
            assertEquals(1, envelope.getItems().size());
            assertEquals(IdentityIssuingRequest.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerIdentity());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityExportTest2() {
        Envelope envelope = new Envelope();
        envelope.addItem(Commons.getIssuerIdentity());
        String exported = envelope.exportToEncoded();
        assertNotNull(exported);
        assertTrue(exported.length() > 0);
        assertTrue(exported.startsWith(Envelope.HEADER));
        assertEquals(2, exported.split(":").length);
    }

    @Test
    void identityImportTest1() {
        try {
            String exported = "Di.eyJpYXQiOiIyMDIyLTA4LTE4VDIwOjI2OjA0Ljc2ODg3N1oiLCJpc3MiOiJiYjdhNzQ1OC0zZjVjLTQ4ZmItYWJmOC0zN2Y3Mzc4ZmEyMTkifQ:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlhdCI6IjIwMjItMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlzcyI6ImNiNTBlNTEyLWQwMjYtNGQyZC04ZDhhLTZiMjQ3NDIzNjA5MiIsInB1YiI6IlNUTi4yZ1hma1VRZ1A2RUxCNFI4QXFpRDc1dXc1QllVUFB6UEx0R0xFRmMyejMzSm9hVDgybSIsInN1YiI6ImJiN2E3NDU4LTNmNWMtNDhmYi1hYmY4LTM3ZjczNzhmYTIxOSIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMzViNDM1ZjgtZDI1OC00ZDMxLWJjMmMtNmEyMjE1NjQwZDhmIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdPQzB4TjFReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFXRjBJam9pTWpBeU1pMHdPQzB4T0ZReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFYTnpJam9pWldaaE1XRTFNamN0TkRJMVlpMDBORGt3TFRnNU5XTXRNV05pTVRObE5qTTJZamc0SWl3aWNIVmlJam9pVTFST0xqSXpUblYzUWtONWIwZG9lR2RIVFdOalJVZExOMGhFZWpsNmVXZzVTMGcyV0hCa2VYaFZWa0Z5ZFhCT1dHZHdVMjV5SWl3aWMzVmlJam9pWTJJMU1HVTFNVEl0WkRBeU5pMDBaREprTFRoa09HRXRObUl5TkRjME1qTTJNRGt5SWl3aWMzbHpJam9pYVc4dVpHbHRaV1p2Y20xaGRDNXlaV1lpTENKMWFXUWlPaUkxTVRnNU1HRmxZUzFqWlRKbExUUTRabU10WVdKaE9DMW1PREZtT1dJeU1EVXlNekVpZlEuWWpJM09ERXdOMlJqWlRsaE4yTXpaUzVoTmprd1l6QmhPV00zTUdZeU9EWTRNelJrWmpZek56RTJZV1EzTXpJek1EQTVOVEJqTW1FeFl6ZGxObU0zWVRrNE56STJPR0V6WVdVeE5EYzFOamRrWWpVNVpEbGpOR0poWkdVNU5qUTNaV1kzWlRVd1pqUTRNREJsTkdJME5EZGhNbVprWldKbE1EbGxObVJrTkdFeU16WTFNek5qTVRabFpHVTJaall3TXc.MDA1MjE3NDUwNDBjNTI0Zi45ZjYwMzI1YjUxY2NiYWIxNTg2MGQ4MjQxNjdkZGE5MjQ0MmI5Nzc2MDllMTNkMzYzOGY2OTAwMTdhMGZiZjhlNTUzYzJhZjA1MzkwNTFjN2NkZDVkZDk0ZWY5NmQwZGZkYTAxYzMyZThiNTI2ZWE4YThhNGNkNjljYzAyODAwOA:YThlNGMxZWJlYWIyMDliZi5hZmVlMjg2ZWY0NDc2MjI2Y2I1OTQ3YjlmMzk5YjQ1Yjk5N2VkNDc3NGQ2MGQwNzc2YWZlZGE1Mjk5YmRmZGZmOWQ0MmIzMTEzZDQxZjAzNDc3OTAyYjMzZjA0YmY2MDI0OWI2ZjgxOTk5ZTNhYzg4ZWM5NDYyM2MwMmIzZDIwNw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-08-18T20:26:04.768877Z"), envelope.getIssuedAt());
            assertNull(envelope.getContext());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Identity.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void identityImportTest2() {
        try {
            String exported = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlhdCI6IjIwMjItMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlzcyI6ImNiNTBlNTEyLWQwMjYtNGQyZC04ZDhhLTZiMjQ3NDIzNjA5MiIsInB1YiI6IlNUTi4yZ1hma1VRZ1A2RUxCNFI4QXFpRDc1dXc1QllVUFB6UEx0R0xFRmMyejMzSm9hVDgybSIsInN1YiI6ImJiN2E3NDU4LTNmNWMtNDhmYi1hYmY4LTM3ZjczNzhmYTIxOSIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMzViNDM1ZjgtZDI1OC00ZDMxLWJjMmMtNmEyMjE1NjQwZDhmIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdPQzB4TjFReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFXRjBJam9pTWpBeU1pMHdPQzB4T0ZReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFYTnpJam9pWldaaE1XRTFNamN0TkRJMVlpMDBORGt3TFRnNU5XTXRNV05pTVRObE5qTTJZamc0SWl3aWNIVmlJam9pVTFST0xqSXpUblYzUWtONWIwZG9lR2RIVFdOalJVZExOMGhFZWpsNmVXZzVTMGcyV0hCa2VYaFZWa0Z5ZFhCT1dHZHdVMjV5SWl3aWMzVmlJam9pWTJJMU1HVTFNVEl0WkRBeU5pMDBaREprTFRoa09HRXRObUl5TkRjME1qTTJNRGt5SWl3aWMzbHpJam9pYVc4dVpHbHRaV1p2Y20xaGRDNXlaV1lpTENKMWFXUWlPaUkxTVRnNU1HRmxZUzFqWlRKbExUUTRabU10WVdKaE9DMW1PREZtT1dJeU1EVXlNekVpZlEuWWpJM09ERXdOMlJqWlRsaE4yTXpaUzVoTmprd1l6QmhPV00zTUdZeU9EWTRNelJrWmpZek56RTJZV1EzTXpJek1EQTVOVEJqTW1FeFl6ZGxObU0zWVRrNE56STJPR0V6WVdVeE5EYzFOamRrWWpVNVpEbGpOR0poWkdVNU5qUTNaV1kzWlRVd1pqUTRNREJsTkdJME5EZGhNbVprWldKbE1EbGxObVJrTkdFeU16WTFNek5qTVRabFpHVTJaall3TXc.MDA1MjE3NDUwNDBjNTI0Zi45ZjYwMzI1YjUxY2NiYWIxNTg2MGQ4MjQxNjdkZGE5MjQ0MmI5Nzc2MDllMTNkMzYzOGY2OTAwMTdhMGZiZjhlNTUzYzJhZjA1MzkwNTFjN2NkZDVkZDk0ZWY5NmQwZGZkYTAxYzMyZThiNTI2ZWE4YThhNGNkNjljYzAyODAwOA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getIssuerId());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Identity.class, envelope.getItems().get(0).getClass());
            try { envelope.verify(Commons.getIssuerKey()); fail("Exception not thrown."); } catch (VerificationException e) { /* all is well */ }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void keyExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope.addItem(Commons.getIssuerKey());
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void keyImportTest1() {
        try {
            String exported = "Di.eyJpYXQiOiIyMDIyLTA4LTE4VDIwOjI4OjQ0LjcxNTk5NVoiLCJpc3MiOiJiYjdhNzQ1OC0zZjVjLTQ4ZmItYWJmOC0zN2Y3Mzc4ZmEyMTkifQ:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjc0NzA2MloiLCJrZXkiOiJTVE4uUFRRVTFLY1l3c1ZUOEFmV1NTbUxxQW9peVF4cnVyd0F0S1djcnRqMnl6VVEzb0VkYXJOd1BkVUFkRm5xM2cxNFlpV2FMS3VOaUF3cERzYkI0b2NIMXE4Q3Z5TWkzIiwicHViIjoiU1ROLjJnWGZrVVFnUDZFTEI0UjhBcWlENzV1dzVCWVVQUHpQTHRHTEVGYzJ6MzNKb2FUODJtIiwidWlkIjoiNjg4ODdmM2EtMjQxNC00M2I5LWJjOTItNzIwMzQ4YjE1NmM5IiwidXNlIjpbInNpZ24iXX0:YThlNGMxZWJlYWIyMDliZi4zMmU1YzAwMDUwMjk4ZmYxZmM2NDcwNDE2MzRkMjlkN2YyNmUyZTBmNmY4NjkwMTU3NDc2ZTJhODA2ZGQ4MzA3N2NiNmY1ZmRkNzA5MjFmZDQwODI3YWZkYWY3MTM5ZWQ2ZWFiNmY2MmQyNzY0MjM4OWI0MGI3NWI3MTQ2MmYwMw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-08-18T20:28:44.715995Z"), envelope.getIssuedAt());
            assertNull(envelope.getContext());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Key.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void dataExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId(), Commons.CONTEXT);
            Data data = new Data(Commons.getAudienceIdentity().getSubjectId(),100);
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
            data.sign(Commons.getIssuerKey());
            envelope.addItem(data);
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void dataImportTest1() {
        try {
            String exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjIwOjA5LjUwMzg0N1oiLCJpc3MiOiJiYjdhNzQ1OC0zZjVjLTQ4ZmItYWJmOC0zN2Y3Mzc4ZmEyMTkifQ:DAT.eyJleHAiOiIyMDIyLTA4LTE4VDIwOjIxOjQ5LjUwNTI3NVoiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjIwOjA5LjUwNTI3NVoiLCJpc3MiOiI0MWFkMzk4Ny1kY2ZkLTQ4MWMtOWYxMi0xYTA0YTUzOTIzNTYiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiMDIwMGZiNjAtNmRkYi00MDJjLThiZjItNzFiNzBlNDcyOWQxIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YThlNGMxZWJlYWIyMDliZi40MjhiMTZiYWY1MDdhNGYwMWVkMjJmNDVmMWRlNDgyZTRhNzNmMzE1ZmZjNjQ2NDMxNDgyOWRhZjg4N2U0ZjgxNzE1NDcwYjYwOTQ1ODg2MDcyNzIyNmM4MDE3YjY0ZGI5ODBhNDg5MTE2ZGY4NzRkMzVjYjYzOTUwMjgyZjkwMA:YThlNGMxZWJlYWIyMDliZi41Y2U2ZDUwZDY5NmRlYWM5MzM0NmM0YjUxZDUwNTdhZjNkOGVjNDNmMmY0YWQ1NGMxN2RiMWE2YjliYmIxY2VmY2U1NGFmNDhmYzNiZGU0OWVhMzE1Njc2NGQwZTk2ZDA2YzU0YTllNjVmYjQ3NzViMTk1OTllNzNlNzA1YWYwZQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-08-18T20:20:09.503847Z"), envelope.getIssuedAt());
            assertEquals(Commons.CONTEXT, envelope.getContext());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Data.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void messageExportTest1() {
        try {
            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getSubjectId(), "Di:ME");
            Message message = new Message(Commons.getAudienceIdentity().getSubjectId(), Commons.getIssuerIdentity().getSubjectId(), 100);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());
            envelope.addItem(message);
            envelope.sign(Commons.getIssuerKey());
            String exported = envelope.exportToEncoded();
            assertNotNull(exported);
            assertTrue(exported.length() > 0);
            assertTrue(exported.startsWith(Envelope.HEADER));
            assertEquals(3, exported.split(":").length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void messageImportTest1() {
        try {
            String exported = "Di.eyJjdHgiOiJEaTpNRSIsImlzcyI6IjBhYTU2MTMzLTc4YjAtNGRkOS05MjhkLTVkN2ZmOWRhNTQ0NSIsImlhdCI6IjIwMjEtMTEtMThUMjA6MDM6MTguMTc2MDI4WiJ9:MSG.eyJ1aWQiOiI5ZDFiNzAyYy1lODQwLTRjZDYtYTNiNy0zZDRlODJjMjY5N2YiLCJhdWQiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJleHAiOiIyMDIxLTExLTE4VDIwOjA0OjU4LjE3NjY3OVoiLCJpYXQiOiIyMDIxLTExLTE4VDIwOjAzOjE4LjE3NjY3OVoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.c7phh6GC0hqaPoBKWKtdyJqMcE3G3v+SXZuygevFIhqkB7do3YhSFWYfJ60DwyX5Bu10+DpWt11vUb+u3yGtCQ:oidP1H5ys88FQkxuhdlL5HVoCg9RdxodA6aD3RxlwaDHVf+iI1+HKKk9kFL6//kaAgTze9wQVrNJG1iQKFtUBQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T20:03:18.176028Z"), envelope.getIssuedAt());
            assertEquals("Di:ME", envelope.getContext());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Message.class, envelope.getItems().get(0).getClass());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

    @Test
    void exportTest1() {
        try {
            Envelope envelope1 = new Envelope(Commons.getIssuerIdentity().getSubjectId());
            envelope1.addItem(Commons.getIssuerIdentity());
            envelope1.addItem(Commons.getIssuerKey().publicCopy());
            envelope1.sign(Commons.getIssuerKey());
            String exported = envelope1.exportToEncoded();

            Envelope envelope2 = Envelope.importFromEncoded(exported);
            envelope2.verify(Commons.getIssuerKey());
            assertEquals(2, envelope2.getItems().size());

            Identity identity = (Identity)envelope2.getItems().get(0);
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), identity.getSubjectId());
            Key key = (Key)envelope2.getItems().get(1);
            assertEquals(Commons.getIssuerKey().getUniqueId(), key.getUniqueId());
            assertNull(key.getSecret());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
    }

}
