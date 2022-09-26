//
//  Commons.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.List;
import java.util.UUID;
import io.dimeformat.Identity.Capability;
import io.dimeformat.exceptions.VerificationException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "io.dimeformat.ref";
    public static final String PAYLOAD = "Racecar is racecar backwards.";
    public static final String MIMETYPE = "text/plain";
    public static final String CONTEXT = "test-context";
    public static final String SIGN_KEY_CONTEXT = "id-key";

    public static String fullHeaderFor(String itemIdentifier) {
        return Envelope.HEADER + ":" + itemIdentifier;
    }

    public static Key getTrustedKey() {
        if (Commons._trustedKey == null) { Commons._trustedKey = Commons.importFromEncoded(Commons._encodedTrustedKey); }
        return Commons._trustedKey;
    }
    
    public static Identity getTrustedIdentity() {
        if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Commons.importFromEncoded(Commons._encodedTrustedIdentity); }
        return Commons._trustedIdentity;
    }

    public static Key getIntermediateKey() {
        if (Commons._intermediateKey == null) { Commons._intermediateKey = Commons.importFromEncoded(Commons._encodedIntermediateKey); }
        return Commons._intermediateKey;
    }
    
    public static Identity getIntermediateIdentity() {
        if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Commons.importFromEncoded(Commons._encodedIntermediateIdentity); }
        return Commons._intermediateIdentity;
    }

    public static Key getIssuerKey() {
        if (Commons._issuerKey == null) { Commons._issuerKey = Commons.importFromEncoded(Commons._encodedIssuerKey); }
        return Commons._issuerKey;
    }
    
    public static Identity getIssuerIdentity() {
        if (Commons._issuerIdentity == null) { Commons._issuerIdentity = Commons.importFromEncoded(Commons._encodedIssuerIdentity); }
        return Commons._issuerIdentity;
    }

    public static Key getAudienceKey() {
        if (Commons._audienceKey == null) { Commons._audienceKey = Commons.importFromEncoded(Commons._encodedAudienceKey); }
        return Commons._audienceKey;
    }
    
    public static Identity getAudienceIdentity() {
        if (Commons._audienceIdentity == null) { Commons._audienceIdentity = Commons.importFromEncoded(Commons._encodedAudienceIdentity); }
        return Commons._audienceIdentity;
    }

    public static void initializeKeyRing() {
        Dime.keyRing.put(Commons.getTrustedIdentity());
    }

    public static void clearKeyRing() {
        Dime.keyRing.clear();
    }

    /// TESTS ///

    @Test
    public void generateCommons() {
        try {
            Commons.clearKeyRing();
            Key trustedKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, Dime.VALID_FOR_1_YEAR * 10, new Capability[]{Capability.GENERIC, Capability.ISSUE});
            assertNotNull(trustedIdentity);
            try { trustedIdentity.verify(); fail("Exception not thrown."); } catch (VerificationException e) { /* all is well */ }
            trustedIdentity.verify(trustedIdentity);
            System.out.println("// -- TRUSTED IDENTITY ---");
            System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

            Dime.keyRing.put(trustedIdentity);
            Key intermediateKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new Capability[]{Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE});
            assertNotNull(intermediateIdentity);
            intermediateIdentity.verify();
            System.out.println("// -- INTERMEDIATE IDENTITY --");
            System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedIntermediateIdentity = \"" + intermediateIdentity.exportToEncoded() + "\";\n");

            Key issuerKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(issuerIdentity);
            issuerIdentity.verify();
            System.out.println("// -- ISSUER IDENTITY (SENDER) --");
            System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
            System.out.println("public static final String _encodedIssuerIdentity = \"" + issuerIdentity.exportToEncoded() + "\";\n");

            Key audienceKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(audienceIdentity);
            audienceIdentity.verify();
            System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
            System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedAudienceIdentity = \"" + audienceIdentity.exportToEncoded() + "\";\n");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjY4MjE4OFoiLCJrZXkiOiJTVE4uVnBNMndqWTZiU3k4Q3I1OFpwdXB0cnY1OW5xNWRhTUM5OGc5TUpuUU00M1RmWlZvQTFSYTVyRWtxakJSTVo3b1J4VFZVS3NDMzZqcEF2TXRwWXVZdkQycTNMcmhlIiwicHViIjoiU1ROLjJTVExaU1F1bkpOdXY0SmFmNlRtYlFTbXNpTTdDMmdRaUdVVHFLcm03ZWdqRWJ5akc0IiwidWlkIjoiMWM4ODdjNzQtYWNiOS00Y2U0LTkwNmEtZWYxMWJlNWJkNmZhIiwidXNlIjpbInNpZ24iXX0";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTA4LTE1VDIwOjA2OjUzLjcyNjQyN1oiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjcyNjQyN1oiLCJpc3MiOiJlZmExYTUyNy00MjViLTQ0OTAtODk1Yy0xY2IxM2U2MzZiODgiLCJwdWIiOiJTVE4uMlNUTFpTUXVuSk51djRKYWY2VG1iUVNtc2lNN0MyZ1FpR1VUcUtybTdlZ2pFYnlqRzQiLCJzdWIiOiJlZmExYTUyNy00MjViLTQ0OTAtODk1Yy0xY2IxM2U2MzZiODgiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjQzOWVlMjAzLWFkZWEtNDUyZS04MzE2LTA4NTQzYWI2NjU3MSJ9.YjI3ODEwN2RjZTlhN2MzZS5jNzdjZDI3NmNkMzVlNTE5OTU1MmJmM2U2NmFmZDI2NTIyMmZjZTZiOWM1Y2ZmZDljZDFmNGI0YTFmMGRhMjAyZjMxY2RhODFhMTU5ZGZkOTRhYTI5Yzk5M2VmZjM2MmZmODQyNDc3MTdkOGZkMWRkZDQ2MzUzODM0ODY1ZjAwOQ";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjc0NDAxN1oiLCJrZXkiOiJTVE4uWmtiTkU4bTZ3VFM4THZCY011QXF2NkFpaVFCMTkzVDhZRVRKUnlFU01RVDlBenpWOGluRFQyUE1RWWhpVmdWOE04dGJkMVJCcG1hRjhrQ1BXeXJ3ajRnUFB1OW5TIiwicHViIjoiU1ROLjIzTnV3QkN5b0doeGdHTWNjRUdLN0hEejl6eWg5S0g2WHBkeXhVVkFydXBOWGdwU25yIiwidWlkIjoiNGYxOGJjNWItNzQxYS00YzQ4LThmYzctZTEyMmY3OTlkMTdiIiwidXNlIjpbInNpZ24iXX0";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0wOC0xN1QyMDowNjo1My43NDU3MTdaIiwiaWF0IjoiMjAyMi0wOC0xOFQyMDowNjo1My43NDU3MTdaIiwiaXNzIjoiZWZhMWE1MjctNDI1Yi00NDkwLTg5NWMtMWNiMTNlNjM2Yjg4IiwicHViIjoiU1ROLjIzTnV3QkN5b0doeGdHTWNjRUdLN0hEejl6eWg5S0g2WHBkeXhVVkFydXBOWGdwU25yIiwic3ViIjoiY2I1MGU1MTItZDAyNi00ZDJkLThkOGEtNmIyNDc0MjM2MDkyIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiI1MTg5MGFlYS1jZTJlLTQ4ZmMtYWJhOC1mODFmOWIyMDUyMzEifQ.YjI3ODEwN2RjZTlhN2MzZS5hNjkwYzBhOWM3MGYyODY4MzRkZjYzNzE2YWQ3MzIzMDA5NTBjMmExYzdlNmM3YTk4NzI2OGEzYWUxNDc1NjdkYjU5ZDljNGJhZGU5NjQ3ZWY3ZTUwZjQ4MDBlNGI0NDdhMmZkZWJlMDllNmRkNGEyMzY1MzNjMTZlZGU2ZjYwMw";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjc0NzA2MloiLCJrZXkiOiJTVE4uUFRRVTFLY1l3c1ZUOEFmV1NTbUxxQW9peVF4cnVyd0F0S1djcnRqMnl6VVEzb0VkYXJOd1BkVUFkRm5xM2cxNFlpV2FMS3VOaUF3cERzYkI0b2NIMXE4Q3Z5TWkzIiwicHViIjoiU1ROLjJnWGZrVVFnUDZFTEI0UjhBcWlENzV1dzVCWVVQUHpQTHRHTEVGYzJ6MzNKb2FUODJtIiwidWlkIjoiNjg4ODdmM2EtMjQxNC00M2I5LWJjOTItNzIwMzQ4YjE1NmM5IiwidXNlIjpbInNpZ24iXX0";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlhdCI6IjIwMjItMDgtMThUMjA6MDY6NTMuNzQ5MzkzWiIsImlzcyI6ImNiNTBlNTEyLWQwMjYtNGQyZC04ZDhhLTZiMjQ3NDIzNjA5MiIsInB1YiI6IlNUTi4yZ1hma1VRZ1A2RUxCNFI4QXFpRDc1dXc1QllVUFB6UEx0R0xFRmMyejMzSm9hVDgybSIsInN1YiI6ImJiN2E3NDU4LTNmNWMtNDhmYi1hYmY4LTM3ZjczNzhmYTIxOSIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMzViNDM1ZjgtZDI1OC00ZDMxLWJjMmMtNmEyMjE1NjQwZDhmIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdPQzB4TjFReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFXRjBJam9pTWpBeU1pMHdPQzB4T0ZReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFYTnpJam9pWldaaE1XRTFNamN0TkRJMVlpMDBORGt3TFRnNU5XTXRNV05pTVRObE5qTTJZamc0SWl3aWNIVmlJam9pVTFST0xqSXpUblYzUWtONWIwZG9lR2RIVFdOalJVZExOMGhFZWpsNmVXZzVTMGcyV0hCa2VYaFZWa0Z5ZFhCT1dHZHdVMjV5SWl3aWMzVmlJam9pWTJJMU1HVTFNVEl0WkRBeU5pMDBaREprTFRoa09HRXRObUl5TkRjME1qTTJNRGt5SWl3aWMzbHpJam9pYVc4dVpHbHRaV1p2Y20xaGRDNXlaV1lpTENKMWFXUWlPaUkxTVRnNU1HRmxZUzFqWlRKbExUUTRabU10WVdKaE9DMW1PREZtT1dJeU1EVXlNekVpZlEuWWpJM09ERXdOMlJqWlRsaE4yTXpaUzVoTmprd1l6QmhPV00zTUdZeU9EWTRNelJrWmpZek56RTJZV1EzTXpJek1EQTVOVEJqTW1FeFl6ZGxObU0zWVRrNE56STJPR0V6WVdVeE5EYzFOamRrWWpVNVpEbGpOR0poWkdVNU5qUTNaV1kzWlRVd1pqUTRNREJsTkdJME5EZGhNbVprWldKbE1EbGxObVJrTkdFeU16WTFNek5qTVRabFpHVTJaall3TXc.MDA1MjE3NDUwNDBjNTI0Zi45ZjYwMzI1YjUxY2NiYWIxNTg2MGQ4MjQxNjdkZGE5MjQ0MmI5Nzc2MDllMTNkMzYzOGY2OTAwMTdhMGZiZjhlNTUzYzJhZjA1MzkwNTFjN2NkZDVkZDk0ZWY5NmQwZGZkYTAxYzMyZThiNTI2ZWE4YThhNGNkNjljYzAyODAwOA";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA4LTE4VDIwOjA2OjUzLjc1MjYxN1oiLCJrZXkiOiJTVE4uQ1NvZVNkYVJwTk5UQlNZYTlaZzRIMmMyOEoyVFFkdnBDc1pxUmNGcmRWVnBKb2txWHV4TVlNc1JvaWhKTlNwbm9ZRXkzSkNVV0IycEpiTG5ReHJCSmlwMzR1VDJuIiwicHViIjoiU1ROLnhWZE1kMVZ2TTM4Q0FXN1lpTmNlVjVqN0ZZalRHc29udG83VlpEYlVnVXZSaVZQQkIiLCJ1aWQiOiJiOWM4YTdjOS1kMTdiLTQ4NTctYjdiMC1kYmRkZmI2MjFmNGUiLCJ1c2UiOlsic2lnbiJdfQ";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDgtMThUMjA6MDY6NTMuNzU0Mzc1WiIsImlhdCI6IjIwMjItMDgtMThUMjA6MDY6NTMuNzU0Mzc1WiIsImlzcyI6ImNiNTBlNTEyLWQwMjYtNGQyZC04ZDhhLTZiMjQ3NDIzNjA5MiIsInB1YiI6IlNUTi54VmRNZDFWdk0zOENBVzdZaU5jZVY1ajdGWWpUR3NvbnRvN1ZaRGJVZ1V2UmlWUEJCIiwic3ViIjoiNDFhZDM5ODctZGNmZC00ODFjLTlmMTItMWEwNGE1MzkyMzU2Iiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIzYzcyMmI4Yi0yZjliLTRhYTQtODg4Yy1lYzkwYzc3ZjVmYjEifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdPQzB4TjFReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFXRjBJam9pTWpBeU1pMHdPQzB4T0ZReU1Eb3dOam8xTXk0M05EVTNNVGRhSWl3aWFYTnpJam9pWldaaE1XRTFNamN0TkRJMVlpMDBORGt3TFRnNU5XTXRNV05pTVRObE5qTTJZamc0SWl3aWNIVmlJam9pVTFST0xqSXpUblYzUWtONWIwZG9lR2RIVFdOalJVZExOMGhFZWpsNmVXZzVTMGcyV0hCa2VYaFZWa0Z5ZFhCT1dHZHdVMjV5SWl3aWMzVmlJam9pWTJJMU1HVTFNVEl0WkRBeU5pMDBaREprTFRoa09HRXRObUl5TkRjME1qTTJNRGt5SWl3aWMzbHpJam9pYVc4dVpHbHRaV1p2Y20xaGRDNXlaV1lpTENKMWFXUWlPaUkxTVRnNU1HRmxZUzFqWlRKbExUUTRabU10WVdKaE9DMW1PREZtT1dJeU1EVXlNekVpZlEuWWpJM09ERXdOMlJqWlRsaE4yTXpaUzVoTmprd1l6QmhPV00zTUdZeU9EWTRNelJrWmpZek56RTJZV1EzTXpJek1EQTVOVEJqTW1FeFl6ZGxObU0zWVRrNE56STJPR0V6WVdVeE5EYzFOamRrWWpVNVpEbGpOR0poWkdVNU5qUTNaV1kzWlRVd1pqUTRNREJsTkdJME5EZGhNbVprWldKbE1EbGxObVJrTkdFeU16WTFNek5qTVRabFpHVTJaall3TXc.MDA1MjE3NDUwNDBjNTI0Zi4zNTA3ZDFhNDM4ODg4NWRiYTNjYWYwMTgyODEzZjhiNTBlNGFkNjdkYmJlMDgzODBiZmY1YWFjOGU3MTQzOWVhMDQ0ZjU5NjViZDNkNzgxMjIwYzg0ZmI1NmM2OGFhYTA1YTIwNTk4YWQwOWY4ZTg5OGY2ZmM3OGQ2Yzc3OGIwNA";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;

    private static <T extends Item> T importFromEncoded(String encoded) {
        try {
            return Item.importFromEncoded(encoded);
        } catch (Exception e) {
            throw new RuntimeException(); // Should not happen
        }
    }

    private static Identity generateIdentity(Key subjectKey, Key issuerKey, Identity issuerIdentity, long validFor, Capability[] capabilities) {
        try {
            UUID subjectId = UUID.randomUUID();
            IdentityIssuingRequest iir = IdentityIssuingRequest.generateIIR(subjectKey, capabilities);
            Identity identity;
            if (issuerIdentity == null) {
                identity = iir.selfIssueIdentity(subjectId, validFor, issuerKey, Commons.SYSTEM_NAME);
            } else {
                identity = iir.issueIdentity(subjectId, validFor, issuerKey, issuerIdentity, true, capabilities, null);
            }
            return identity;
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
        return null;
    }

}
