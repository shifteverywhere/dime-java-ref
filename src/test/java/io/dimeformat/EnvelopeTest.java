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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class EnvelopeTest {

    @Test
    void getItemTest1() {
        try {
            Message message = new Message(UUID.randomUUID(), UUID.randomUUID(), -1, "message-context");
            Key key = Key.generateKey(KeyType.IDENTITY, "key-context");
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
            String exported = "Di:MSG.eyJpc3MiOiIxODVlNjc0ZS1jYzQ5LTRlNmMtOGRhNi1mNDE1NDY1ZjJiMDUiLCJ1aWQiOiJmMmU3MGU4My00YmJjLTQ1N2YtOWQzMC04YjJhYmRlMjFhZTciLCJhdWQiOiIzZThjYTdiNS0yYmFmLTQ3MzItOWUyNS0zMjVkYTliMTRjYmUiLCJpYXQiOiIyMDIyLTA0LTE1VDE1OjU0OjU3LjcwMjY5MloiLCJjdHgiOiJtZXNzYWdlLWNvbnRleHQifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.NFnMpo/MeutxUzlIe7TYeTKN3prEoses/so3OstGURMgSsFa0fvepFsGpLuWmZI6BVkeMVVbHwKCIKvfP5KCBw:KEY.eyJ1aWQiOiI3YjA5MjJkOC02MWUzLTRlZjMtYmY2NS05OWNjOWY0OTZhMDIiLCJwdWIiOiIyVERYZG9OdlBnTDI1ZEo2aHh5ZVVIZGttTmJnUlpMM3JNYU5aWVA4OWVyU3ZGY2JIUkhwWUpzUEwiLCJpYXQiOiIyMDIyLTA0LTE1VDE1OjU0OjU3LjcwMDgxNFoiLCJjdHgiOiJrZXktY29udGV4dCIsImtleSI6IlMyMVRaU0xSam5yUUVxS293UGNLd1dNN21tUGV2Rkc3QUtROFhjdmZNVEphZUtpQktSMk5kY2liSmVYd3V3ZEF4d2VDVjZGckpYZTFTUmthenlnQ1I2dzhqaTFWUVJQNlg3ZVQifQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            // Context
            Item item1 = envelope.getItem("key-context");
            assertTrue(item1 instanceof Key);
            assertEquals("key-context", item1.getContext());
            Item item2 = envelope.getItem("message-context");
            assertTrue(item2 instanceof Message);
            assertEquals("message-context", item2.getContext());
            // Unique ID
            UUID uid1 = UUID.fromString("7b0922d8-61e3-4ef3-bf65-99cc9f496a02");
            Item item3 = envelope.getItem(uid1);
            assertTrue(item3 instanceof Key);
            assertEquals(uid1, item3.getUniqueId());
            UUID uid2 = UUID.fromString("f2e70e83-4bbc-457f-9d30-8b2abde21ae7");
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
            String exported = "Di:IIR.eyJ1aWQiOiIzOWY0NmZjZC02YmQxLTQwZWQtODg3ZS02ZTBhZGYyOTczNmQiLCJjYXAiOlsiZ2VuZXJpYyJdLCJwdWIiOiIyVERYZG9OdkpwcGFvYW9BQnAyRnJXM0dGVTl5QTJRSDVXN0JBb2NtZ29qcDc1ek0xRHIyeEczTUgiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjMyOjE3LjI1OTY2OVoifQ.8C9TzVO+/35NZ0H5vsi7QX9CvkF3Vof3IpwRwRgmi1zAU0nDLm2RzEN/JOnU1arD3yGRfyDFNvSlfWgdDZicCg";
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
            String exported = "Di.eyJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjQ0OjUyLjc1MDAxMloifQ:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw:ZSEKjL0RtBSUDNhDUXSxt8zCdBX/M2Q2c2cJ22MKe59Mj3qWTMFG8nl+NagF5hx2uNL703DtIAl8OItSjNQcAQ";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T19:44:52.750012Z"), envelope.getIssuedAt());
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
            String exported = "Di:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw";
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
            String exported = "Di.eyJpc3MiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJpYXQiOiIyMDIxLTExLTE4VDE5OjU1OjQzLjY5Njk2MFoifQ:KEY.eyJ1aWQiOiI4ZjEyNDgzMS01NzBlLTQyMmUtYjNiMS00NzlhNzI3ZTY2ZGEiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg1NzI2M1oiLCJrZXkiOiJTMjFUWlNMS1B2MVhDajdNVGN6V3ZkQVRUU3M5ek4xc3VKNUFEWnlZaldFcnZBaG1WZEduUDYxYm1HRlVodUFmcUg0UkQ1eGdTTjZaY2RhR1prMno4aXhSRnJVU05ZQmhzQnZyIn0:eGmbvRS7gkk9UPN7n2CX4Su5XtdL3qEoRwOqvEixS4mAkr+6qbD3ss4d9+VAMT00OBRKUH61uCoC0FYWTr8VBA";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(UUID.fromString("0aa56133-78b0-4dd9-928d-5d7ff9da5445"), envelope.getIssuerId());
            assertEquals(Instant.parse("2021-11-18T19:55:43.696960Z"), envelope.getIssuedAt());
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
            data.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8), Commons.MIMETYPE);
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
            String exported = "Di.eyJpc3MiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJ1aWQiOiJmNjdhNGRmOS1jZTJkLTQ1NjctYTZkOC1jMzRiZTA2ZDE5NTIiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjMzOjUyLjQ5MDkxMVoiLCJjdHgiOiJpby5kaW1lZm9ybWF0LnRlc3QifQ:DAT.eyJtaW0iOiJ0ZXh0L3BsYWluIiwiaXNzIjoiNjQ5NDY5OTEtOTBkNi00M2JhLWI2MjMtNmE3NjA5OWEyY2I4IiwidWlkIjoiYjRhZWQzYjAtYTdhZi00NTcxLTkzY2QtYjkwMzBlZmY5NzE1IiwiZXhwIjoiMjAyMi0wNS0zMFQwNzozNTozMi45MTM0MzZaIiwiaWF0IjoiMjAyMi0wNS0zMFQwNzozMzo1Mi45MTM0MzZaIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.foxqMrA7TRCtF9abKuVpFsZe9jpIuniVD99Vz8eb5gnuAm36V9038LnXo5/OaF0zs8XJBuGZPVYDOXVqk+4ABg:EpQ7dWvirzs7j+ABFl1nwOPHnh1UPxguvswVHPVKueOCOA6tbkFV+p3p9ri1rYtlvFgbmtYrLa8geFGz04aoCw";
            Envelope envelope = Envelope.importFromEncoded(exported);
            assertFalse(envelope.isAnonymous());
            assertEquals(Commons.getIssuerIdentity().getSubjectId(), envelope.getIssuerId());
            assertEquals(Instant.parse("2022-05-30T07:33:52.490911Z"), envelope.getIssuedAt());
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
            message.setPayload("Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8));
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
