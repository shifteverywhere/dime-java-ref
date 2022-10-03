//
//  Commons.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import java.util.List;
import java.util.UUID;

import io.dimeformat.enums.IdentityCapability;
import io.dimeformat.enums.KeyCapability;
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
            Key trustedKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, Dime.VALID_FOR_1_YEAR * 10, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.ISSUE});
            assertNotNull(trustedIdentity);
            try { trustedIdentity.verify(); fail("Exception not thrown."); } catch (VerificationException e) { /* all is well */ }
            trustedIdentity.verify(trustedIdentity);
            System.out.println("// -- TRUSTED IDENTITY ---");
            System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

            Dime.keyRing.put(trustedIdentity);
            Key intermediateKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY, IdentityCapability.ISSUE});
            assertNotNull(intermediateIdentity);
            intermediateIdentity.verify();
            System.out.println("// -- INTERMEDIATE IDENTITY --");
            System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedIntermediateIdentity = \"" + intermediateIdentity.exportToEncoded() + "\";\n");

            Key issuerKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY});
            assertNotNull(issuerIdentity);
            issuerIdentity.verify();
            System.out.println("// -- ISSUER IDENTITY (SENDER) --");
            System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
            System.out.println("public static final String _encodedIssuerIdentity = \"" + issuerIdentity.exportToEncoded() + "\";\n");

            Key audienceKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY});
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
    private static final String _encodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjA2MDM5MFoiLCJrZXkiOiJTVE4uYTlhaVJSNndObWtVUlpOeUVNbTFGV0NqekFDYU5rYTNzRGlLaGY5bnJwdUpub21tb2ZXRXRaUHBZQVlpOUFVeXJ2UTdtREtSUThocFdqUXNxWVVXR0hWOVhFZksiLCJwdWIiOiJTVE4uZFgycVJtWWZ2eFRNdVZIeml2a1hjUU0zQWROMm44aEhoRkJ2ZnNENDhXVGVzcjRZVSIsInVpZCI6ImIwYTM1YjA2LTM0NWItNDhjMC04MDYyLWMwOWU5MWM3ODFlMCJ9";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTA5LTMwVDE0OjQxOjUzLjEyMTUwMFoiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjEyMTUwMFoiLCJpc3MiOiJiNDNjNDgyOC0wOTYxLTRiZDYtYjdhYy1lNzZiOTg4YmFmZjAiLCJwdWIiOiJTVE4uZFgycVJtWWZ2eFRNdVZIeml2a1hjUU0zQWROMm44aEhoRkJ2ZnNENDhXVGVzcjRZVSIsInN1YiI6ImI0M2M0ODI4LTA5NjEtNGJkNi1iN2FjLWU3NmI5ODhiYWZmMCIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMTU3NGZkZDEtMDRkOC00MjRjLTgyYjItZjkxMDFkNTliYjI3In0.MjY3MDU3ZmQ5N2UyMDNmNi41MjI1NDExMjhhOGNhZTViYWI5MTQ1ZDdjYTFlNWIxMzYyZTU3Mzg5ZjE5NjQyMjhiNjZmZWYwZDdjYmUwYzM0YTM1YzA3YWRmMzIwMWFmNDU1ZmMwNjBiM2E5NmY5MzlkNTQ3ZGIwZGFmZTMzNWJmN2MyZjc1YmFhNjVjNjAwYg";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjE0MjUyOFoiLCJrZXkiOiJTVE4uMjlxdktkVUpwU0dQM0o0MXJaNXgzZDdlWDRqcnZkTnpuV1VHRlRtb3pteVNUMTNDZzZTcFhiUjdHUERXN0hObVJhNGdVbmJuTW9MYzdHUzg2TmlxY050dHR1UE1IIiwicHViIjoiU1ROLm1rVU1vZ2VvaFU5Q3V1cDlVV3ZxMTJ6U29VNjRlTFVXVVhxMTlmOXBZSjNhSlZGUEMiLCJ1aWQiOiJjMGViN2JlZC01OTFlLTQwMjEtOTcwZC1lODgxMTQ3ZmE0OGQifQ";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0xMC0wMlQxNDo0MTo1My4xNDQzNjhaIiwiaWF0IjoiMjAyMi0xMC0wM1QxNDo0MTo1My4xNDQzNjhaIiwiaXNzIjoiYjQzYzQ4MjgtMDk2MS00YmQ2LWI3YWMtZTc2Yjk4OGJhZmYwIiwicHViIjoiU1ROLm1rVU1vZ2VvaFU5Q3V1cDlVV3ZxMTJ6U29VNjRlTFVXVVhxMTlmOXBZSjNhSlZGUEMiLCJzdWIiOiJjZTU3OGIzNi1iYTJjLTRjZjEtYWU1Yy0zN2M1NjVhZjZlMTEiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjUyOTM2ZmQ0LWVmNWMtNDllNS05OTkyLTJlZTBlZDAxZDMwMiJ9.MjY3MDU3ZmQ5N2UyMDNmNi5jYzM3MmNkY2EzMDBkZDU5NDY2NGZhM2E1YzZkM2Q1MjJjNjRlODlmMjQ5Njc0ODUwMjcwNTQxY2UyNjVkMGNjZTVhZTRlNjE2MmQ3MDJjMDE4MmY2YjU2NDJkODE5NDE1MmNkNzg3Y2Y1NTEwNzBmZmUxNmZiM2EzNzg1MzEwNA";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjE0NjgxN1oiLCJrZXkiOiJTVE4uNjZXbXBGSjQ2NXREcVFMZHBKMVBWdk5MZ1Q3OUhSTVRLa0U3ZjlKTEF3NDdBb29GNUo5eFRibVBvQ25haFNpSk40TldXR3E0UlVya0w5NFVnNnBUVERoTFNuZkozIiwicHViIjoiU1ROLjJLVlFNU0ZCZ0R4QXQyRndmMjdOdGc5d3Q5V3k2WG42cm1YNDhjWXpyUms1NVQyRlBtIiwidWlkIjoiNDY4MDFmMjktODU1Ny00OWFhLWJiNTctNTBlZmRiMjhkZmZmIn0";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlhdCI6IjIwMjItMTAtMDNUMTQ6NDE6NTMuMTQ5Njk0WiIsImlzcyI6ImNlNTc4YjM2LWJhMmMtNGNmMS1hZTVjLTM3YzU2NWFmNmUxMSIsInB1YiI6IlNUTi4yS1ZRTVNGQmdEeEF0MkZ3ZjI3TnRnOXd0OVd5NlhuNnJtWDQ4Y1l6clJrNTVUMkZQbSIsInN1YiI6ImVmNGQ1YmYwLWY5ZWQtNDNlOS1iYTdkLTAwY2Q0MTBjMmYyYyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiY2ZkODFlZjktMjExNy00NGEyLWIwMWEtZDUyOTUxZGVjN2UxIn0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB3TWxReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB3TTFReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFYTnpJam9pWWpRell6UTRNamd0TURrMk1TMDBZbVEyTFdJM1lXTXRaVGMyWWprNE9HSmhabVl3SWl3aWNIVmlJam9pVTFST0xtMXJWVTF2WjJWdmFGVTVRM1YxY0RsVlYzWnhNVEo2VTI5Vk5qUmxURlZYVlZoeE1UbG1PWEJaU2pOaFNsWkdVRU1pTENKemRXSWlPaUpqWlRVM09HSXpOaTFpWVRKakxUUmpaakV0WVdVMVl5MHpOMk0xTmpWaFpqWmxNVEVpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJalV5T1RNMlptUTBMV1ZtTldNdE5EbGxOUzA1T1RreUxUSmxaVEJsWkRBeFpETXdNaUo5Lk1qWTNNRFUzWm1RNU4yVXlNRE5tTmk1all6TTNNbU5rWTJFek1EQmtaRFU1TkRZMk5HWmhNMkUxWXpaa00yUTFNakpqTmpSbE9EbG1NalE1TmpjME9EVXdNamN3TlRReFkyVXlOalZrTUdOalpUVmhaVFJsTmpFMk1tUTNNREpqTURFNE1tWTJZalUyTkRKa09ERTVOREUxTW1Oa056ZzNZMlkxTlRFd056Qm1abVV4Tm1aaU0yRXpOemcxTXpFd05B.MDFiODQxNmIzMjk0NmJmYi43ZDFlZjgwMWQ5YWIyMzQ0ZGZiMTQxODhjZTZiZWU0Yjk4MTNjYzJmZjI4NzNlNzQ3Mzc5NDBkMjViNDc4ZDk0MTY5MjlkM2I1ZWMzNjUwMTY3MzIxN2MwZjk4ZTA4MTM4ZGNiMGJmZGJjYzFkOWYzNTU2OTg5MDI1OTRmOGYwNQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjE1NDI2N1oiLCJrZXkiOiJTVE4uTk05dlJmdnhCWjVDWjZXWUg4U1I1cHV5TmJYOTFINmZDS3o5ZDZWQVR5QzU3WVhoaWpvV2VDUHJLMTl3clZobWQ1OFgzeXpYMlBzWlhpOTJMRWIzTVVTZFJnbldiIiwicHViIjoiU1ROLjVzcmVLWEZETWJhRVR6QmRVVXBLNURibm9KcmExRmU3ZGVaRE1GaXJ4VWdkNkI3cnMiLCJ1aWQiOiJkZTljYzgxZC0zMmNiLTRmNmItYjkwZS1kYjg3ZTAwMzExNGEifQ";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMDNUMTQ6NDE6NTMuMTU2NzY0WiIsImlhdCI6IjIwMjItMTAtMDNUMTQ6NDE6NTMuMTU2NzY0WiIsImlzcyI6ImNlNTc4YjM2LWJhMmMtNGNmMS1hZTVjLTM3YzU2NWFmNmUxMSIsInB1YiI6IlNUTi41c3JlS1hGRE1iYUVUekJkVVVwSzVEYm5vSnJhMUZlN2RlWkRNRmlyeFVnZDZCN3JzIiwic3ViIjoiY2MzMDVmNzQtNjFkYy00ZWNlLWJkNTAtY2E4ODVkMGMzNjlmIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiJlYmE3YzcxOC0wNjBjLTQ4MDgtYjM1MS00Nzc5MzAyNjUwMmQifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB3TWxReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB3TTFReE5EbzBNVG8xTXk0eE5EUXpOamhhSWl3aWFYTnpJam9pWWpRell6UTRNamd0TURrMk1TMDBZbVEyTFdJM1lXTXRaVGMyWWprNE9HSmhabVl3SWl3aWNIVmlJam9pVTFST0xtMXJWVTF2WjJWdmFGVTVRM1YxY0RsVlYzWnhNVEo2VTI5Vk5qUmxURlZYVlZoeE1UbG1PWEJaU2pOaFNsWkdVRU1pTENKemRXSWlPaUpqWlRVM09HSXpOaTFpWVRKakxUUmpaakV0WVdVMVl5MHpOMk0xTmpWaFpqWmxNVEVpTENKemVYTWlPaUpwYnk1a2FXMWxabTl5YldGMExuSmxaaUlzSW5WcFpDSTZJalV5T1RNMlptUTBMV1ZtTldNdE5EbGxOUzA1T1RreUxUSmxaVEJsWkRBeFpETXdNaUo5Lk1qWTNNRFUzWm1RNU4yVXlNRE5tTmk1all6TTNNbU5rWTJFek1EQmtaRFU1TkRZMk5HWmhNMkUxWXpaa00yUTFNakpqTmpSbE9EbG1NalE1TmpjME9EVXdNamN3TlRReFkyVXlOalZrTUdOalpUVmhaVFJsTmpFMk1tUTNNREpqTURFNE1tWTJZalUyTkRKa09ERTVOREUxTW1Oa056ZzNZMlkxTlRFd056Qm1abVV4Tm1aaU0yRXpOemcxTXpFd05B.MDFiODQxNmIzMjk0NmJmYi5jZWQ2ZThkYWMyYWMyOTMzODI5ZDhmZGY3NWE0Y2IwMzE5N2FmNDY3MjVmMDQ2NjE3NDBmZDE5ODJiM2FjZjJmOGNiZmIwNDVlZTk3YWEwYWU0NzZlZDEzMTA5MmU1MTAyNDg1NzU2M2VhYmNhOTc0ZDEwYTIwOGI0YTgxNDgwMg";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;

    private static <T extends Item> T importFromEncoded(String encoded) {
        try {
            return Item.importFromEncoded(encoded);
        } catch (Exception e) {
            throw new RuntimeException(); // Should not happen
        }
    }

    private static Identity generateIdentity(Key subjectKey, Key issuerKey, Identity issuerIdentity, long validFor, IdentityCapability[] capabilities) {
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
