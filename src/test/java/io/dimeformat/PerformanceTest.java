//
//  PerformanceTest.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.Claim;
import io.dimeformat.enums.IdentityCapability;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.KeyCapability;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class PerformanceTest {

    static final int PERFORMANCE_ROUNDS = 10;

    @Test
    void signaturePerformanceTest() throws Exception {

        System.out.println("-- Signature performance tests --\n");
        System.out.println("Number of rounds: " + PERFORMANCE_ROUNDS + "\n");

        Key key = Key.generateKey(KeyCapability.SIGN);
        Message message = new Message(UUID.randomUUID(),
                UUID.randomUUID(),
                Dime.VALID_FOR_1_HOUR,
                Commons.CONTEXT);
        message.setPayload(Commons.PAYLOAD.getBytes(), Commons.MIMETYPE);

        System.out.print("* Running signing tests...");
        System.out.flush();
        long totalStart = System.nanoTime();
        long start = System.nanoTime();

        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            message.sign(key);
            message.strip();
        }

        long end = System.nanoTime();
        double result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        System.out.print("* Running verification tests...");
        System.out.flush();

        message.sign(key);

        start = System.nanoTime();

        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            message.verify(key);
        }

        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        long totalEnd = System.nanoTime();
        double totalResult = PerformanceTest.convertToSeconds(totalEnd - totalStart);
        System.out.println("\nTOTAL: " + totalResult + "s");

    }

    @Test
    void identityPerformanceTest() {

        //Dime.crypto.setDefaultSuiteName("DSC");

        System.out.println("-- Identity performance tests --\n");
        System.out.println("Number of rounds: " + PERFORMANCE_ROUNDS + "\n");

        System.out.print("Initializing trust chain...");
        Key rootKey = Key.generateKey(KeyCapability.SIGN);
        Identity rootIdentity = Commons.generateIdentity(rootKey,
                rootKey,
                null,
                Dime.VALID_FOR_1_HOUR,
                new IdentityCapability[] { IdentityCapability.ISSUE });
        Dime.keyRing.put(rootIdentity);

        Key interKey = Key.generateKey(KeyCapability.SIGN);
        Identity interIdentity =  Commons.generateIdentity(interKey,
                rootKey,
                rootIdentity,
                Dime.VALID_FOR_1_HOUR,
                new IdentityCapability[] { IdentityCapability.ISSUE });
        System.out.println(" DONE");

        long totalStart = System.nanoTime();

        System.out.print("* Running key generation tests...");
        System.out.flush();
        Key key = null;
        long start = System.nanoTime();
        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            key = Key.generateKey(List.of(KeyCapability.SIGN));
        }
        long end = System.nanoTime();
        double result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        assertNotNull(key);

        System.out.print("* Running IIR generation tests...");
        System.out.flush();
        IdentityCapability[] caps = new IdentityCapability[] { IdentityCapability.GENERIC };
        IdentityIssuingRequest iir = null;
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                iir = IdentityIssuingRequest.generateIIR(key, caps);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        assertNotNull(iir);

        System.out.print("* Running identity issuing tests...");
        System.out.flush();
        Identity identity = null;
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                identity = iir.issueIdentity(UUID.randomUUID(),
                        Dime.VALID_FOR_1_YEAR,
                        interKey,
                        interIdentity,
                        true,
                        caps,
                        null);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        assertNotNull(identity);

        System.out.print("* Running identity verification from root tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                identity.verify();
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity verification from node tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                identity.verify(interIdentity);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity exporting tests...");
        System.out.flush();
        String dime = null;
        start = System.nanoTime();
        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            dime = identity.exportToEncoded();
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        assertNotNull(dime);

        System.out.print("* Running identity importing tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                Item.importFromEncoded(dime);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        long totalEnd = System.nanoTime();
        double totalResult = PerformanceTest.convertToSeconds(totalEnd - totalStart);
        System.out.println("\nTOTAL: " + totalResult + "s");

    }

    @Test
    void decodingPerformanceTest1() {

        Key key = Key.generateKey(KeyCapability.SIGN);

        byte[] secretBytes = key.getKeyBytes(Claim.KEY);
        byte[] publicBytes = key.getKeyBytes(Claim.PUB);

        System.out.println("-- Key decoding performance tests --\n");
        System.out.println("Number of rounds: " + PERFORMANCE_ROUNDS + "\n");
        long totalStart = System.nanoTime();

        String base58key = Base58.encode(publicBytes);
        System.out.print("* Running base 58 decoding tests... [" + base58key + "]");
        System.out.flush();
        long start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                byte[] decodedKey = Base58.decode(base58key);
                decodedKey = null;
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        long end = System.nanoTime();
        double result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        String base64key = Utility.toBase64(secretBytes);
        System.out.print("* Running base 64 decoding tests... [" + base64key + "]");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                    byte[] decodedKey = Utility.fromBase64(base64key);
                    decodedKey = null;
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        String hexkey = Utility.toHex(secretBytes);
        System.out.print("* Running hexadecimal decoding tests... [" + hexkey + "]");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                byte[] decodedKey = Utility.fromHex(hexkey);
                decodedKey = null;
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        long totalEnd = System.nanoTime();
        double totalResult = PerformanceTest.convertToSeconds(totalEnd - totalStart);
        System.out.println("\nTOTAL: " + totalResult + "s");

    }

    @Test
    void signatureTest() {
        try {

            System.out.println("-- Signing/verification tests --\n");
            System.out.println("Number of rounds: " + PERFORMANCE_ROUNDS + "\n");

            Message message = new Message(Commons.getAudienceIdentity().getClaim(Claim.SUB),
                    Commons.getIssuerIdentity().getClaim(Claim.SUB),
                    Dime.VALID_FOR_1_HOUR,
                    Commons.CONTEXT);
            message.setPayload(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
            message.sign(Commons.getIssuerKey());

            Envelope envelope = new Envelope(Commons.getIssuerIdentity().getClaim(Claim.SUB), Commons.CONTEXT);
            envelope.addItem(Commons.getIssuerIdentity());
            envelope.addItem(Commons.getAudienceIdentity());
            envelope.addItem(Commons.getTrustedIdentity());
            envelope.addItem(Commons.getIntermediateIdentity());
            envelope.addItem(message);
            envelope.addItem(Commons.getIssuerKey().publicCopy());
            envelope.addItem(Commons.getIntermediateKey());
            envelope.addItem(Commons.getTrustedKey());
            envelope.addItem(Commons.getAudienceKey());

            Key legacySigningKey = Key.generateKey(List.of(KeyCapability.SIGN), Dime.NO_EXPIRATION, null, null, "DSC");

            long totalStart = System.nanoTime();
            System.out.print("* Running legacy signing test...");
            System.out.flush();
            long start = System.nanoTime();
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                envelope.sign(legacySigningKey);
                envelope.strip();
            }
            long end = System.nanoTime();
            double result = PerformanceTest.convertToSeconds(end - start);
            System.out.println(" DONE \n\t - Total: " + result+ "s\n");

            envelope.sign(legacySigningKey);

            totalStart = System.nanoTime();
            System.out.print("* Running legacy verification test...");
            System.out.flush();
            start = System.nanoTime();
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                envelope.verify(legacySigningKey);
            }
            end = System.nanoTime();
            result = PerformanceTest.convertToSeconds(end - start);
            System.out.println(" DONE \n\t - Total: " + result+ "s\n");

            Key signingKey = Key.generateKey(KeyCapability.SIGN);

            System.out.print("* Running thumbprint signing tests...");
            System.out.flush();
            start = System.nanoTime();
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                envelope.sign(signingKey);
                envelope.strip();
            }
            end = System.nanoTime();
            result = PerformanceTest.convertToSeconds(end - start);
            System.out.println(" DONE \n\t - Total: " + result+ "s\n");

            envelope.sign(signingKey);

            System.out.print("* Running thumbprint verification tests...");
            System.out.flush();
            start = System.nanoTime();
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                envelope.verify(signingKey);
            }
            end = System.nanoTime();
            result = PerformanceTest.convertToSeconds(end - start);
            System.out.println(" DONE \n\t - Total: " + result+ "s\n");

            long totalEnd = System.nanoTime();
            double totalResult = PerformanceTest.convertToSeconds(totalEnd - totalStart);
            System.out.println("\nTOTAL: " + totalResult + "s");

        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    private static double convertToSeconds(long nanoTime) {
        return (double) nanoTime / 1_000_000_000;
    }

}
