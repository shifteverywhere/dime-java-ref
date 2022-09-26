//
//  PerformanceTest.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import io.dimeformat.enums.KeyType;
import org.junit.jupiter.api.Test;
import io.dimeformat.Identity.Capability;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

public class PerformanceTest {

    public static final int PERFORMANCE_ROUNDS = 10;

    @Test
    public void identityPerformanceTest() {

        System.out.println("-- Identity performance tests --\n");
        System.out.println("Number of rounds: " + PERFORMANCE_ROUNDS + "\n");
        long totalStart = System.nanoTime();

        Commons.initializeKeyRing();
        Capability[] caps = new Capability[] { Capability.GENERIC, Capability.IDENTIFY };
        List<Key> keyList = new ArrayList<>();
        List<IdentityIssuingRequest> iirList = new ArrayList<>();
        List<Identity> identityList = new ArrayList<>();
        List<String> dimeList = new ArrayList<>();

        System.out.print("* Running key generation tests...");
        System.out.flush();
        long start = System.nanoTime();
        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            Key key = Key.generateKey(KeyType.IDENTITY);
            keyList.add(key);
        }
        long end = System.nanoTime();
        double result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result+ "s\n");

        System.out.print("* Running IIR generation tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(keyList.get(i), caps);
                iirList.add(iir);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity issuing tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                IdentityIssuingRequest iir = iirList.get(i);
                Identity identity = iir.issueIdentity(UUID.randomUUID(), Dime.VALID_FOR_1_YEAR, Commons.getIntermediateKey(), Commons.getIntermediateIdentity(), true, caps, null, null, null);
                identityList.add(identity);
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity verification from root tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                Identity identity = identityList.get(i);
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
                Identity identity = identityList.get(i);
                identity.verify(Commons.getIntermediateIdentity());
            }
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity exporting tests...");
        System.out.flush();
        start = System.nanoTime();
        for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
            Identity identity = identityList.get(i);
            String dime = identity.exportToEncoded();
            dimeList.add(dime);
        }
        end = System.nanoTime();
        result = PerformanceTest.convertToSeconds(end - start);
        System.out.println(" DONE \n\t - Total: " + result + "s\n");

        System.out.print("* Running identity importing tests...");
        System.out.flush();
        start = System.nanoTime();
        try {
            for(int i = 0; i < PerformanceTest.PERFORMANCE_ROUNDS; i++) {
                String dime = dimeList.get(i);
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

    private static double convertToSeconds(long nanoTime) {
        return (double) nanoTime / 1_000_000_000;
    }

}
