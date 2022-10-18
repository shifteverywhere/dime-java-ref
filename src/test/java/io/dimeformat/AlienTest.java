//
//  AlienTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.enums.KeyCapability;
import io.dimeformat.keyring.IntegrityState;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests DiME envelopes/items from other platforms (C#/.NET)
 */
class AlienTest {

    @Test
    void keyTest1() {
        try {
            String alienKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE4VDE3OjMzOjEwLjgzMTAxNVoiLCJrZXkiOiJTVE4uRWU4dnNCeFNFNDRvaUFWS2N2OTJnY3FBMnZ6aXpCdDVRblpZaEtDTFFKN29KYmJXVjhXY1lpYnF2b2FKWUFSZkZVeXNEeXdNOHFkeGZVYXZTMkJwQVVvVVg5N29jIiwicHViIjoiU1ROLkxjZGtpbVlmdlFZSHoxOUVUR0MzdWhNaVlhSmJidEo2SGFYdVV5aENEYVc4MWtmdDIiLCJ1aWQiOiJlY2Q2OTAwZC04MjQzLTQ5NjgtYmQ5OC1hOTg4ZjlkMWIyMzcifQ";
            Key key = Item.importFromEncoded(alienKey);
            assertNotNull(key);
            assertTrue(key.hasCapability(KeyCapability.SIGN));
            assertEquals(Instant.parse("2022-10-18T17:33:10.831015Z"), key.getClaim(Claim.IAT));
            assertEquals("STN.Ee8vsBxSE44oiAVKcv92gcqA2vzizBt5QnZYhKCLQJ7oJbbWV8WcYibqvoaJYARfFUysDywM8qdxfUavS2BpAUoUX97oc", key.getSecret());
            assertEquals("STN.LcdkimYfvQYHz19ETGC3uhMiYaJbbtJ6HaXuUyhCDaW81kft2", key.getPublic());
            assertEquals(UUID.fromString("ecd6900d-8243-4968-bd98-a988f9d1b237"), key.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void keyTest2() {
        try {
            String alienKey = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiY3R4IjoidGVzdC1jb250ZXh0IiwiaWF0IjoiMjAyMi0xMC0xOFQxNzo0Mjo1MC42OTgwOTJaIiwicHViIjoiU1ROLmFGTmZENldnQmROMTNGOExkN0xUdGF0MmVibnA5VzROa2V2dWI5OWdTaDIxS3RtWHMiLCJ1aWQiOiI1MTUyNTI3Ny05ODU3LTQ3MjgtODhjYS05MTJmYjExYmIyY2EifQ";
            Key key = Item.importFromEncoded(alienKey);
            assertNotNull(key);
            assertTrue(key.hasCapability(KeyCapability.EXCHANGE));
            assertEquals(Commons.CONTEXT, key.getClaim(Claim.CTX));
            assertEquals(Instant.parse("2022-10-18T17:42:50.698092Z"), key.getClaim(Claim.IAT));
            assertNull(key.getSecret());
            assertEquals("STN.aFNfD6WgBdN13F8Ld7LTtat2ebnp9W4Nkevub99gSh21KtmXs", key.getPublic());
            assertEquals(UUID.fromString("51525277-9857-4728-88ca-912fb11bb2ca"), key.getClaim(Claim.UID));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void identityIssuingRequestTest1() {
        try {
            String alienIir = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTEwLTE4VDE3OjUwOjAzLjE1MDQ5MVoiLCJwdWIiOiJTVE4uMjVNeHZRWmR1YlprbjhTNGR3aXN2MUNCYWpya1paWm9nNU0yMWtLcHdCUjNhQlVkUDgiLCJ1aWQiOiJiZDA5MTZlYy1hYjZhLTRmMzgtYjQ4MC1mOTg1ZWZhY2Y3ZTQifQ.YWZjMmY2MmUzOTBhOWEwNS41MWVhZjc1NzhlOWViYjAzMTc5M2ExYjMzODFlMDIxYTdlNzEzYzJkZmIwZWZhMTU0YzUyMWM4MzZkMmE2MWZmN2UyYTM4NGYxZDRlMDFhYzNmMjdhMDIwNWFmNDYwNjdkMzU2NDFjNzFjNDIxM2I3OTdhYTBiODNlMGU4NzkwNw";
            IdentityIssuingRequest iir = Item.importFromEncoded(alienIir);
            assertNotNull(iir);
            assertTrue(iir.wantsCapability(IdentityCapability.GENERIC));
            assertEquals(Instant.parse("2022-10-18T17:50:03.150491Z"), iir.getClaim(Claim.IAT));
            Key key = iir.getPublicKey();
            assertNotNull(key);
            assertEquals("STN.25MxvQZdubZkn8S4dwisv1CBajrkZZZog5M21kKpwBR3aBUdP8", key.getPublic());
            assertEquals(UUID.fromString("bd0916ec-ab6a-4f38-b480-f985efacf7e4"), iir.getClaim(Claim.UID));
            assertEquals(IntegrityState.COMPLETE, iir.verify(key));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void identityIssuingRequestTest2() {
        try {
            String alienIir = "Di:IIR.eyJjYXAiOlsiZ2VuZXJpYyJdLCJpYXQiOiIyMDIyLTEwLTE4VDE3OjUwOjAzLjE1MDQ5MVoiLCJwdWIiOiJTVE4uMjVNeHZRWmR1YlprbjhTNGR3aXN2MUNCYWpya1paWm9nNU0yMWtLcHdCUjNhQlVkUDgiLCJ1aWQiOiJiZDA5MTZlYy1hYjZhLTRmMzgtYjQ4MC1mOTg1ZWZhY2Y3ZTQifQ.YWZjMmY2MmUzOTBhOWEwNS41MWVhZjc1NzhlOWViYjAzMTc5M2ExYjMzODFlMDIxYTdlNzEzYzJkZmIwZWZhMTU0YzUyMWM4MzZkMmE2MWZmN2UyYTM4NGYxZDRlMDFhYzNmMjdhMDIwNWFmNDYwNjdkMzU2NDFjNzFjNDIxM2I3OTdhYTBiODNlMGU4NzkwNw";
            IdentityIssuingRequest iir = Item.importFromEncoded(alienIir);
            assertNotNull(iir);
            IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
            Commons.initializeKeyRing();
            Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_DAY, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps,
                    caps);
            assertNotNull(identity);
            assertEquals(IntegrityState.COMPLETE, identity.verify());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void identityTest1() {
        try {
            String alienIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMThUMTg6MjA6MDEuNzAyMjk5WiIsImlhdCI6IjIwMjItMTAtMThUMTg6MjA6MDEuNzAyMjk5WiIsImlzcyI6ImNlZGYyYjZhLTI5ZTItNDRlNS05NjFhLWM0NzNlNGI1NjM3OCIsInB1YiI6IlNUTi4ycmt3NXByd3RUV3dkQnczR3ByOWRVOVhGczE1NmFGNFJYSkpOOEZGZWoxNHdpQnY5eiIsInN1YiI6Ijk1NTg1YzNkLTIxOGItNGYzMS1hYzUzLWRjNzkzN2E2ODcxMiIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiZGM1OGFiNjQtNDIxYS00YTlkLTg5NjQtMjQ5YWVmODYyNDU0In0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB4TmxReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB4TjFReE9EbzFNem96TlM0ek9UY3hNVGxhSWl3aWFYTnpJam9pWkRSaU5qQTRORFl0TURJNE5TMDBOak5qTFdJME5qVXRPV0kzTlRnM016TmhOREZtSWl3aWNIVmlJam9pVTFST0xtaGxabGhNYTFWVFJuWkJlVkpYZEVWQldHaDJibGxIUzJWaGRGTTRXRlZxZG1Gdk9XTmpkbEpDVWtWaWJ6SnpSa2dpTENKemRXSWlPaUpqWldSbU1tSTJZUzB5T1dVeUxUUTBaVFV0T1RZeFlTMWpORGN6WlRSaU5UWXpOemdpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJbVE0TVRNNE4yTXpMV0V6TWprdE5ETmpNQzA1TURVNUxXSmhNMkZsWmpWbE9XVmtaU0o5Lk5qRXdZbUUyTkdRME16RmlaR0kyWVM0ek5XSXlOamcwTnpKbE5XSmxNV013WTJRek1EUXdNamRoTnpOa016Z3pNbVF5TnpSaU1XWTFaR1JpWm1JMFpHTmhPR1JoTXpreU1qY3hPREJsTVRWbE9XWTRZV1V4WTJJMFpqbGxaVEpsTVdaaFlqZ3laRFE0WldFd1l6Z3dNMlkwTVRJelpUZ3lNbUkwTXpsbU56QTRZamN3TnpZeFlUTXhZMlEzTlRnd01B.NDFjNjlmZDZkYzk5NjkyOC5iZTQ4OGU0MjQxYThlMGExZTE5ZDMxMmQ2MTJlODEwZDBkNTgzMmM0ZmIzYWZjZjY2MTAxYmFmMDBkYjdhMzkxYWU0Y2Y2NzI2M2QwN2UwOTkzZWQ2NDA2MTlhZDkyMDYxMGI4ZWI4YTc5ZmE0YzE2MzYxMmEzZDA3OGI3MjIwMA";
            Identity identity = Item.importFromEncoded(alienIdentity);
            assertNotNull(identity);
            assertTrue(identity.hasCapability(IdentityCapability.GENERIC));
            assertTrue(identity.hasCapability(IdentityCapability.IDENTIFY));
            assertEquals(Instant.parse("2023-10-18T18:20:01.702299Z"), identity.getClaim(Claim.EXP));
            assertEquals(Instant.parse("2022-10-18T18:20:01.702299Z"), identity.getClaim(Claim.IAT));
            assertEquals(UUID.fromString("cedf2b6a-29e2-44e5-961a-c473e4b56378"), identity.getClaim(Claim.ISS));
            assertEquals("STN.2rkw5prwtTWwdBw3Gpr9dU9XFs156aF4RXJJN8FFej14wiBv9z", identity.getPublicKey().getPublic());
            assertEquals(UUID.fromString("95585c3d-218b-4f31-ac53-dc7937a68712"), identity.getClaim(Claim.SUB));
            assertEquals(Commons.SYSTEM_NAME, identity.getClaim(Claim.SYS));
            assertEquals(UUID.fromString("dc58ab64-421a-4a9d-8964-249aef862454"), identity.getClaim(Claim.UID));
            assertNotNull(identity.getTrustChain());
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void dataTest1() {
        try {
            String alienData = "Di:DAT.eyJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTEwLTE4VDE4OjMxOjA2LjkzMTA5N1oiLCJpYXQiOiIyMDIyLTEwLTE4VDE4OjMwOjA2LjkzMTA5N1oiLCJpc3MiOiIxNmQxYjBjOS0xN2Q5LTQ3MTAtYWI4ZS1jNmI1ZWVkYjA4NTMiLCJtaW0iOiJ0ZXh0L3BsYWluIiwidWlkIjoiOWFiMDE5YmItMGE3OS00ZWVhLTg1ZGEtOGI1MjE3OWZiMWRkIn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            Data data = Item.importFromEncoded(alienData);
            assertNotNull(data);
            assertEquals(Commons.CONTEXT, data.getClaim(Claim.CTX));
            assertEquals(Instant.parse("2022-10-18T18:31:06.931097Z"), data.getClaim(Claim.EXP));
            assertEquals(Instant.parse("2022-10-18T18:30:06.931097Z"), data.getClaim(Claim.IAT));
            assertEquals(UUID.fromString("16d1b0c9-17d9-4710-ab8e-c6b5eedb0853"), data.getClaim(Claim.ISS));
            assertEquals(Commons.MIMETYPE, data.getClaim(Claim.MIM));
            assertEquals(UUID.fromString("9ab019bb-0a79-4eea-85da-8b52179fb1dd"), data.getClaim(Claim.UID));
            assertEquals(Commons.PAYLOAD, new String(data.getPayload(), StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void tagTest1() {
        try {
        String alienKey =
                    "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTE4VDE4OjQ4OjUxLjk1NDAzMloiLCJwdWIiOiJTVE4uMmU2RmVKTFR0dExpbUN0N29UcXBXRUxreXp2UXdNdnpwVFcxWUtLQVdjem91cWZEREwiLCJ1aWQiOiI0NDM2MDc3YS0zYTNlLTQyZGQtYTM4Mi1iZjUyMmNlMWMxMTgifQ";
        String alienTag =
                    "Di:TAG.eyJpc3MiOiI2NTAxMzE5OS00ZTRhLTQ0MDQtOGYwYS1mNDc1MmVhNzdkZGUiLCJsbmsiOiJEQVQuMTBiZDA3MWEtN2FkMC00ZTI2LTliNzgtMzA5YTc5MjUyMDg1LjRkMTBhYTI1Yjg0NWE2OWUxNGE4ZjdiYjBlZDA3NTA4ZTI3OWI3MTNkYzUwMDBiZTNkMjVkYTgzOWU2YTc2YjciLCJ1aWQiOiIyZGY5MjhmMy00ZWNjLTRjYjUtOTMxNC03MmNkMjc5ZGUzZDMifQ.MzgzY2Y4NzUxYTMwMWNiZC4yY2UzZTVmYjJkZmM1NDQ0MjA0ZjU2OWY3OGM1MWQxYTBjMmQ3MTBhMmZhNDhkYmU2N2IyZjk0MWU2ZTFkMTE5NGFmMjVjNDA5YjdhOTA5ZjI3MWVkOWNkMmEwY2JlYjcwZWU3MjM0NTQxYzBiZDM0OTc3NDQzMjk4MWEzOTMwZQ";
        String localData =
                    "Di:DAT.eyJpYXQiOiIyMDIyLTEwLTE4VDE4OjQxOjIxLjExNzg2OVoiLCJpc3MiOiI4YTdjYTlmOS01MmMxLTRkMjQtOTZhNC0yNWM0ODBhMTMxODQiLCJ1aWQiOiIxMGJkMDcxYS03YWQwLTRlMjYtOWI3OC0zMDlhNzkyNTIwODUifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            Key key = Item.importFromEncoded(alienKey);
            assertNotNull(key);
            Tag tag = Item.importFromEncoded(alienTag);
            assertNotNull(tag);
            assertEquals(UUID.fromString("65013199-4e4a-4404-8f0a-f4752ea77dde"), tag.getClaim(Claim.ISS));
            assertEquals(UUID.fromString("2df928f3-4ecc-4cb5-9314-72cd279de3d3"), tag.getClaim(Claim.UID));
            Data data = Item.importFromEncoded(localData);
            assertNotNull(data);
            assertEquals(IntegrityState.COMPLETE, tag.verify(key, List.of(data)));
            assertEquals(IntegrityState.ERR_LINKED_ITEM_MISMATCH, tag.verify(key, List.of(key)));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    @Test
    void envelopeTest1() {
        try {
            String localExchangeKey = "Di:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyMi0xMC0xN1QxODoxMDowOS41MTc2NDFaIiwia2V5IjoiU1ROLndpTHNHYkxRbVlDcW5IUWs0eXRaVWgzeHNQYUhSYjhkVExTOHB0Y1htVGh3SnI1NGkiLCJwdWIiOiJTVE4uMlZ1Z2pWeWtEaVZURDNFaHI0dE1vdW0zaG9aZjZVSDliVzZ1YlhXYTNISkJtQVlQRjEiLCJ1aWQiOiJhNGZmZTRmNS01ZDdmLTRmYzQtOWM1ZC03ZmFmYTYyOGQ4MGUifQ";
            String alienEnvelope = "Di:MSG.eyJhdWQiOiI1YWYyNTAyOC04NDE3LTRhM2MtODMwOC1mMzc3NmRkZWEzMzEiLCJjdHgiOiJ0ZXN0LWNvbnRleHQiLCJleHAiOiIyMDIyLTEwLTE5VDE5OjE1OjA1Ljk0NzE1MVoiLCJpYXQiOiIyMDIyLTEwLTE4VDE5OjE1OjA1Ljk0NzE1MVoiLCJpc3MiOiJmZGM2YTAzNC03ZDIyLTQwZjAtYWVhYy01NTE4MGUyMjRiMTQiLCJ1aWQiOiIzODhlMjRmMS03ZTczLTRjYzktYjdmZi04ZDQyZTJmY2I0NDUifQ.6yFXG/dTFgu/dqQme44TxkIAhHBtkM/DIgHjbk1b0lhhRtnRkE3UTsiipMomRcNdrvqqqtC4JSkrkGYDgojUwT22xjpw.MzFhMDYyN2JlZjk1NjNiZC4yOWMxZTVlYzk4NGQ0ZWUxZDM5YmFhZDFiYzJlOTBhNTIzOWQxMmIwY2IxOTE3YjM4NDBmOGViZmE5ZmM1YTlkZGM2N2U5NTBhYzg1NGI5MTJmMzEyNTQxMDM5Y2I0N2YxZWYzMGE2OTY0NTdjY2IyMWJiMjljNThmOWZlMTYwMw:KEY.eyJjYXAiOlsiZXhjaGFuZ2UiXSwiaWF0IjoiMjAyMi0xMC0xN1QxODowMjoxMy40NTIzNzVaIiwicHViIjoiU1ROLjJmaGQ5ektXNFFReWJQYlBkckNaZUthek1MdFVadkVNVkh6VGE3WlJ3VVppdndjZFgzIiwidWlkIjoiMmUxMjY0NjMtYWVkZC00MWYwLWE3ZGYtNzY4OTZlOGFkMmU3In0";
            Envelope envelope = Envelope.importFromEncoded(alienEnvelope);
            assertNotNull(envelope);
            assertEquals(2, envelope.getItems().size());
            Key alienExchangeKey = (Key) envelope.getItem(UUID.fromString("2e126463-aedd-41f0-a7df-76896e8ad2e7"));
            assertNotNull(alienExchangeKey);
            Message message = (Message) envelope.getItem(UUID.fromString("388e24f1-7e73-4cc9-b7ff-8d42e2fcb445"));
            assertNotNull(message);
            Key exchangeKey = Item.importFromEncoded(localExchangeKey);
            assertNotNull(exchangeKey);
            byte[] payload = message.getPayload(alienExchangeKey, exchangeKey);
            assertNotNull(payload);
            assertEquals(Commons.PAYLOAD, new String(payload, StandardCharsets.UTF_8));
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

}
