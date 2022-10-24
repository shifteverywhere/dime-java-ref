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

import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.exceptions.IntegrityStateException;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class KeyRingTest {

    @BeforeEach
    void clearKeyRing() {
        Dime.keyRing.clear();
    }

    @Test
    void noKeyRingTest1() {
        Commons.clearKeyRing();
        assertTrue(Dime.keyRing.isEmpty());
        Commons.initializeKeyRing();
        assertFalse(Dime.keyRing.isEmpty());
    }

    @Test
    void noKeyRingTest2() {
        assertEquals(IntegrityState.FAILED_NO_KEY_RING, Commons.getAudienceIdentity().verify());
        assertTrue(Dime.keyRing.isEmpty());
    }

    @Test
    void verifyTest1() {
        try {
            Commons.initializeKeyRing();
            assertEquals(IntegrityState.COMPLETE, Commons.getAudienceIdentity().verify());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest2() {
        try {
            Commons.initializeKeyRing();
            UUID subjectId = UUID.randomUUID();
            Key key = Key.generateKey(KeyCapability.SIGN);
            IdentityCapability[] caps = new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.ISSUE};
            Identity identity = IdentityIssuingRequest.generateIIR(key, caps).selfIssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, key, Commons.SYSTEM_NAME);
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, identity.verify());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest3() {
        try {
            Commons.initializeKeyRing();
            Key trustedKey = Key.generateKey(KeyCapability.SIGN);
            Dime.keyRing.put(trustedKey);
            Key issuerKey = Key.generateKey(KeyCapability.SIGN);
            IdentityCapability[] issuerCaps = new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.ISSUE};
            Identity issuerIdentity = IdentityIssuingRequest.generateIIR(issuerKey, issuerCaps).selfIssueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, issuerKey, Commons.SYSTEM_NAME);
            IdentityCapability[] caps = new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY};
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(Key.generateKey(KeyCapability.SIGN), caps);
            Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_MINUTE, issuerKey, issuerIdentity, false, caps, null, null, null);
            assertFalse(identity.verify().isValid());
            identity.sign(trustedKey); // signs the identity with another trusted key
            assertTrue(identity.verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest4() {
        try {
            Key trustedKey = Key.generateKey(KeyCapability.SIGN);
            Dime.keyRing.put(trustedKey);
            Data data = new Data(UUID.randomUUID());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(trustedKey);
            assertTrue(data.verify().isValid());
            Dime.keyRing.remove(trustedKey);
            assertEquals(IntegrityState.COMPLETE, data.verify(trustedKey));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest5() {
        try {
            Key trustedKey = Key.generateKey(KeyCapability.SIGN);
            Dime.keyRing.put(trustedKey);
            Dime.keyRing.put(Key.generateKey(KeyCapability.SIGN));
            Data data = new Data(UUID.randomUUID());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(trustedKey);
            assertTrue(data.verify().isValid());
            Dime.keyRing.remove(trustedKey);
            assertEquals(IntegrityState.FAILED_KEY_MISMATCH, data.verify());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void verifyTest6() {
        try {
            Key trustedKey = Key.generateKey(KeyCapability.SIGN);
            Data data = new Data(UUID.randomUUID());
            data.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            data.sign(trustedKey);
            Key importedKey = Item.importFromEncoded(trustedKey.publicCopy().exportToEncoded());
            Dime.keyRing.put(importedKey);
            assertTrue(data.verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void keyRingTest1() {
        Commons.initializeKeyRing();
        assertEquals(1, Dime.keyRing.size());
        Key key = Key.generateKey(KeyCapability.SIGN);
        Dime.keyRing.put(key);
        assertEquals(2, Dime.keyRing.size());
        Dime.keyRing.remove(key);
        assertEquals(1, Dime.keyRing.size());
        Dime.keyRing.clear();
        assertEquals(0, Dime.keyRing.size());
        assertTrue(Dime.keyRing.isEmpty());
    }

    @Test
    void keyRingTest2() {
        Commons.initializeKeyRing();
        assertTrue(Dime.keyRing.containsItem(Commons.getTrustedIdentity()));
        Dime.keyRing.remove(Commons.getTrustedIdentity());
        assertFalse(Dime.keyRing.containsItem(Commons.getTrustedIdentity()));
    }

    @Test
    void keyRingTest3() {
        try {
            Key trustedKey = Key.generateKey(KeyCapability.SIGN);
            Dime.keyRing.put(trustedKey);
            Key publicKey = trustedKey.publicCopy();
            Dime.keyRing.containsItem(publicKey);
            String encoded = publicKey.exportToEncoded();
            Key importedKey = Item.importFromEncoded(encoded);
            assertTrue(Dime.keyRing.containsItem(importedKey));
            Dime.keyRing.remove(importedKey);
            assertFalse(Dime.keyRing.containsItem(trustedKey));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void exportTest1() {
        try {
            Commons.initializeKeyRing();
            Dime.keyRing.put(Key.generateKey(KeyCapability.SIGN));
            String encoded = Dime.keyRing.exportToEncoded(Commons.getTrustedKey());
            assertNotNull(encoded);
            assertTrue(encoded.startsWith(Envelope.HEADER));
            String[] components = encoded.split(":");
            assertEquals(4, components.length);
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest1() {
        try {
            assertEquals(0, Dime.keyRing.size());
            String encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjE2OjMwLjYxMjkwMloiLCJrZXkiOiJEU0MuOFU2bldkQzVZTnpVUmRoVTF2czZ6d1FxYVFGeW5Ic1QyVlk4WDA0bWJpQVhTWE1Hc2YwdGhjNE1FVVN5RUVOWUpQRU55K0VMYUlFZXVaOU8rS1l5a1EiLCJwdWIiOiJEU0MuRjBsekJySDlMWVhPREJGRXNoQkRXQ1R4RGN2aEMyaUJIcm1mVHZpbU1wRSIsInVpZCI6IjllZDY1YTQ5LThhMmItNDhkOC1iZWNjLWViNGQ5YjkwMWUyZSJ9:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTEwLTIxVDIyOjA0OjA5LjAyMzIyNFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjAyMzIyNFoiLCJpc3MiOiIxNzNmNTJkNi0yNjdjLTQ4OTUtODQ3My0yMTcwMTYwZjM4NmMiLCJwdWIiOiJEU0MubUhSSDNYL1g4TUo2M1ZoUFYyNFlhaUt3VWYwTUdNVWp5MHBONmlIb1Q0USIsInN1YiI6IjE3M2Y1MmQ2LTI2N2MtNDg5NS04NDczLTIxNzAxNjBmMzg2YyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiN2JmNzljN2UtZDQxMi00MWQ1LTg3N2ItOTgyNzI4Y2FmZTIyIn0.MzJkMTQzYzJkMDYyMzA2Yi5hZmJhYjcwY2MyZDUyNzAxMTMzZjFlM2RlNzAzMGIzZDFjODQ1YjcyOGI5NjRkODRkMmUwOTcxNTU1MGVkNWFlODMxZjljZTdjYjhjMDMxYTZlNTFjOGFlZmQ5ZTBkOGNiMTVlNzgxMzc0NTljMzE2ZmFlZDgwNzFkZGM0MjEwZg:MzJkMTQzYzJkMDYyMzA2Yi5kNjAyYmRhNjJlNzFhMGRlY2JhNjVjMjYyMzAzMjUyY2RkOGQxZWYxMzQxYjBmMDQ0YTVjYjgzMDUzNDg4ZjhkNDhmMTFlMmFlYjg3MDU2MDg3NTBiM2RlZTQyNDkwZTE1YWY0ZTViYmM3MTczZDFkNTQxZjhiMzg5MjhkZTMwMw";
            Dime.keyRing.importFromEncoded(encoded, Commons.getTrustedKey());
            assertEquals(2, Dime.keyRing.size());
            assertTrue(Commons.getAudienceIdentity().verify().isValid());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void importTest2() {
        try {
            assertEquals(0, Dime.keyRing.size());
            String encoded = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTA5LTMwVDE0OjQxOjUzLjEyMTUwMFoiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjEyMTUwMFoiLCJpc3MiOiJiNDNjNDgyOC0wOTYxLTRiZDYtYjdhYy1lNzZiOTg4YmFmZjAiLCJwdWIiOiJTVE4uZFgycVJtWWZ2eFRNdVZIeml2a1hjUU0zQWROMm44aEhoRkJ2ZnNENDhXVGVzcjRZVSIsInN1YiI6ImI0M2M0ODI4LTA5NjEtNGJkNi1iN2FjLWU3NmI5ODhiYWZmMCIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMTU3NGZkZDEtMDRkOC00MjRjLTgyYjItZjkxMDFkNTliYjI3In0.MjY3MDU3ZmQ5N2UyMDNmNi41MjI1NDExMjhhOGNhZTViYWI5MTQ1ZDdjYTFlNWIxMzYyZTU3Mzg5ZjE5NjQyMjhiNjZmZWYwZDdjYmUwYzM0YTM1YzA3YWRmMzIwMWFmNDU1ZmMwNjBiM2E5NmY5MzlkNTQ3ZGIwZGFmZTMzNWJmN2MyZjc1YmFhNjVjNjAwYg:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTA2VDEzOjIxOjQ5LjU4OTQyMFoiLCJrZXkiOiJTVE4uRkhCb2tlRkVoSm1ndkVhcXBoV05UbWdjblQ4N3ZhU0RDRGY3aHRxdDlZR0hFYzRVNmRlWHFTdEZjUDczNnpRWktpZjZ0VFJWVVN0b0gxREFBWk4xdjF6REpIOTU0IiwicHViIjoiU1ROLlVWM3Z6b0JnUUdieXppS1YyZnVhSEtIczlkYnI5UVVqOGt2UDExeE5SRjRtRWRIVnIiLCJ1aWQiOiIzNTEyNjg4Yi0wYWQ2LTQ1MjItYjVkYi05Mzk4MTliODc2NDYifQ";
            try {
                Dime.keyRing.importFromEncoded(encoded, Commons.getTrustedKey());
            } catch (IntegrityStateException e) {
                assertEquals(IntegrityState.FAILED_NO_SIGNATURE, e.state);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}