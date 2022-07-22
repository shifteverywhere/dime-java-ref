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
            String exported = "Di:MSG.eyJpc3MiOiJkMThhM2ExYi05Y2I2LTQ4MGEtYTJlZC05NGU2NzMwZTVlMzQiLCJ1aWQiOiIwYTQ2YWVkNy0yYzkyLTQwNDQtYmMyMC0yMTc0Y2IwNjA0MmQiLCJhdWQiOiI3YTAyMzkzZS1kMTVkLTQ3NDYtOTU0Mi1hZDljYmUwNzUxYzgiLCJpYXQiOiIyMDIyLTA1LTMwVDE3OjI1OjMxLjQ0NjkxNloiLCJjdHgiOiJtZXNzYWdlLWNvbnRleHQifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.EBiQVW1sKZgKXEg0qDNoxXGUZXhvO8NfxMWn9YL8zhkVU7jp3q2a8p+5dzlRW1AJXwVdk7iH1jhJMux0DGbpBg:KEY.eyJ1aWQiOiIxMWYxNzllZi0yOWIwLTRlZjAtYjA0Yi0xZjU3MTk5ZTJjZjQiLCJwdWIiOiJEU1ROKzJObWlCMXZVUEhTQzJ6ZW82WWc5REJTUzRXWFN3RUgzS3JVMXpUQmpoOHZVdEt4eFlEIiwiaWF0IjoiMjAyMi0wNS0zMFQxNzoyNTozMS43Mjc3MDRaIiwidXNlIjpbInNpZ24iXSwiY3R4Ijoia2V5LWNvbnRleHQiLCJrZXkiOiJEU1ROK2FEWnRzYUhpb2dvVHU5bVh1NmpaYmNMb3hqUThoWlBoMnhGblJReGJ2VEtvVHdiQUt0YWV1ZEFEUDR2TVRLbm5Ec21hRzJzdHF4ZlozaEY1d21YMzNXZXpQVEg0WSJ9";
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
        envelope.addItem(Key.generateKey(KeyType.IDENTITY));
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
            String exported = "Di:IIR.eyJ1aWQiOiJiNjM4NGM3Yi1hYzFlLTRhY2UtYTBjNC1kZjU1ZGY0OWM1MmEiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiJEU1ROKzJDTWVQZHZ4VkxxcEhxcG1aeVNUaWNnQjV2OE5KZFBlMnlnRnJldDk2TGZWSEJnbXYyIiwiaWF0IjoiMjAyMi0wNS0zMFQxODowMjozNS4yOTg3MDJaIn0.SGwn25l5uXzVB3vs10cOn+MGUU2kFpEicCA09LYIdXieUnQxhbj7WT//IFKJ4un57B7L0vmYJXj9p8MyVezHBg";
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
            String exported = "Di.eyJpc3MiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJ1aWQiOiIyMzJkZTY2OC04ODU0LTQ5MDEtYTIyYi1jMTBkMWNiYjMwZTciLCJpYXQiOiIyMDIyLTA1LTMwVDE4OjAzOjExLjg5MDMwMVoifQ:ID.eyJ1aWQiOiJjMTAwMDZhZC0zOGJhLTQ2ZDMtYWE1OS02YTYzNGIyMjMzNTMiLCJzdWIiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImRjZDMyMDcwLWI5OTYtNGE1Mi04MGI2LWI3Mjg2NzczY2MyMSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoiLCJwdWIiOiJEU1ROK0w3WjlnWENOdWF2M2twYnRqRE1XZ200WWRTZXF0TXNOR05XMXEzN0FLbWF0UXFKREwiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoifQ.SUQuZXlKMWFXUWlPaUkwWlRGak1tTTBPUzAwWVdJMkxUUTVZekV0WWpoaFl5MHlaV1U1TkRZek9XVmxNMlVpTENKemRXSWlPaUprWTJRek1qQTNNQzFpT1RrMkxUUmhOVEl0T0RCaU5pMWlOekk0TmpjM00yTmpNakVpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWW1Rek5tWmtNamN0WWpFNVpDMDBZV1ZoTFRneU1XUXRNRGRsWkdVNVpEVXdNMkZrSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURVdE1qbFVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSXNJbkIxWWlJNklrUlRWRTRyVEVjMlptdDZlVmxZTjNNM09FdGFNM05HYVU1dmNsVnZRMEV5UlhsS1JEWjZWbFEzVjFoMVJrVjBUVTE2ZW1sSGJTSXNJbWxoZENJNklqSXdNakl0TURVdE16QlVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSjkuYzgxVCtDaFRLN1RXai9mQzBUTUIrTjFkd1RURVVJb01lQUFFNVB5R0x1SzFsbThkZ1Z5WVFQTnRTeHVyY3ZZOXJsZk1OZ3poUUFrZ3VTbm44dkJ1Qnc.vzjmxBAyp2HX3RlWydjGRWsCLOojiXPZQOwEcdcSf+fVq9yWjHkNmJWjsQfxS0El4fDu7WdBidkdNMD7zhgGCw:GAfjZ9aZhGk2bPi1EJSlSQzGrXfZbgQGxlJuZw8gzlJl91bocDfpUgsGSH7vAhApvOvmQuflNOVWCUM8zK70AA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("6ce4a7b7-0587-407e-9f95-9d1cec1afd79"), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-05-30T18:03:11.890301Z"), envelope.getIssuedAt());
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
            String exported = "Di:ID.eyJ1aWQiOiJjMTAwMDZhZC0zOGJhLTQ2ZDMtYWE1OS02YTYzNGIyMjMzNTMiLCJzdWIiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImRjZDMyMDcwLWI5OTYtNGE1Mi04MGI2LWI3Mjg2NzczY2MyMSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoiLCJwdWIiOiJEU1ROK0w3WjlnWENOdWF2M2twYnRqRE1XZ200WWRTZXF0TXNOR05XMXEzN0FLbWF0UXFKREwiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoifQ.SUQuZXlKMWFXUWlPaUkwWlRGak1tTTBPUzAwWVdJMkxUUTVZekV0WWpoaFl5MHlaV1U1TkRZek9XVmxNMlVpTENKemRXSWlPaUprWTJRek1qQTNNQzFpT1RrMkxUUmhOVEl0T0RCaU5pMWlOekk0TmpjM00yTmpNakVpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWW1Rek5tWmtNamN0WWpFNVpDMDBZV1ZoTFRneU1XUXRNRGRsWkdVNVpEVXdNMkZrSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURVdE1qbFVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSXNJbkIxWWlJNklrUlRWRTRyVEVjMlptdDZlVmxZTjNNM09FdGFNM05HYVU1dmNsVnZRMEV5UlhsS1JEWjZWbFEzVjFoMVJrVjBUVTE2ZW1sSGJTSXNJbWxoZENJNklqSXdNakl0TURVdE16QlVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSjkuYzgxVCtDaFRLN1RXai9mQzBUTUIrTjFkd1RURVVJb01lQUFFNVB5R0x1SzFsbThkZ1Z5WVFQTnRTeHVyY3ZZOXJsZk1OZ3poUUFrZ3VTbm44dkJ1Qnc.vzjmxBAyp2HX3RlWydjGRWsCLOojiXPZQOwEcdcSf+fVq9yWjHkNmJWjsQfxS0El4fDu7WdBidkdNMD7zhgGCw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertTrue(envelope.isAnonymous());
            assertNull(envelope.getIssuerId());
            assertEquals(1, envelope.getItems().size());
            assertEquals(Identity.class, envelope.getItems().get(0).getClass());
            try {
                envelope.verify(Commons.getIssuerKey());
            } catch (IllegalStateException e) { return; } // All is well
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e); 
        }
        fail("Should not happen.");
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
            String exported = "Di.eyJpc3MiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJ1aWQiOiIxZTY5MzQ3OC01MDIyLTQ5NGUtODIwZS01NjlmZjc4ZTZlNTYiLCJpYXQiOiIyMDIyLTA1LTMwVDE4OjA0OjU2LjU0MzEwMVoifQ:KEY.eyJ1aWQiOiI2ODBmMmZiMi1mMGE1LTRkMGUtODNiNy0yMmExOTViMzJjODQiLCJwdWIiOiJEU1ROK0w3WjlnWENOdWF2M2twYnRqRE1XZ200WWRTZXF0TXNOR05XMXEzN0FLbWF0UXFKREwiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5MTc5OFoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROK2FHb0ZSSFQ4Y243eFdjNWdtYUVmRU05MTh2QzJvZ2hGNkpTNGJ5S2k3cmJRVEU0MjR6blpwOXRXU0M0VDVSeDVGZHByMU5XTE5kcnFBMUFFYVhObXB5MTZVa0V4RiJ9:Fq69NSCs8U+Lv+l0MNZbW+OC3brxv6QjJmjte2rPZr22GjzEwcCczNBAXHghaL197rYLCn4QRYjLCpOXjyK9Ag";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("6ce4a7b7-0587-407e-9f95-9d1cec1afd79"), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-05-30T18:04:56.543101Z"), envelope.getIssuedAt());
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
            String exported = "Di.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJpYXQiOiIyMDIyLTA2LTMwVDA3OjExOjU1LjEyMzA0NloiLCJpc3MiOiIyZmMyMTA4NC1iNWVkLTQ5MjAtODlmMy03MTZiNGZmMmJmM2IifQ:DAT.eyJleHAiOiIyMDIyLTA2LTMwVDA3OjEzOjM1LjEyNDM0M1oiLCJpYXQiOiIyMDIyLTA2LTMwVDA3OjExOjU1LjEyNDM0M1oiLCJpc3MiOiJiZmI0NTViOC0zYTc0LTRiYWYtYWRkMS1lNDEwNzZkNWZmZTQiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiYjVjNjJiN2ItNTIzMC00MzQxLTg4MTYtMDk0NDE3M2M4ZjFjIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MTJhMTE3OTM1OTgwNDgzMC43ODgyMTI4NDc0Y2VhYzhmZDY5NjE0MTU2ZmVkY2RjNDEyZmU5NDBjMjAxNDk2MWRmM2JiZmZlYTkwODkyZDFlNTZkZDJlZjU5NTRlZGRkMDQxNWZjODZiN2Q2ZWQ4YjQzZWViZjdjYTUwYjVkYmE5YjNlZTUxNTI4ZWNmZWQwMw:MTJhMTE3OTM1OTgwNDgzMC4xYTVhMmViNGE0ZjZhOGMzZDU4OGI2MTc3YjdjNGM3M2UzZGU3ODEyNjg5ZDY2NzI4ZWZkNGMyZTZjYzNlZjI2Zjk1ZTEzN2ExMjY2NDFkYTczNzg3OGIxM2MyZDFjOThkODljNDdjNDVkYWRkZGQyMTllYTZlOTlkMTA1ODEwZA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-06-30T07:11:55.123046Z"), envelope.getIssuedAt());
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
