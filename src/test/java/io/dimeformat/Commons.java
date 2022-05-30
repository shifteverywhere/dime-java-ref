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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.List;
import java.util.UUID;

import io.dimeformat.enums.KeyUsage;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "dime-java-ref";
    public static final String PAYLOAD = "Racecar is racecar backwards.";
    public static final String MIMETYPE = "text/plain";
    public static final String CONTEXT = "io.dimeformat.test";
    public static final String SIGN_KEY_CONTEXT = "id-key";

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

    /// TESTS ///

    @Test
    public void generateCommons() {
        Dime.setTrustedIdentity(null);
        Key trustedKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
        Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, Dime.VALID_FOR_1_YEAR * 10, new Capability[] { Capability.GENERIC, Capability.ISSUE });
        assertNotNull(trustedIdentity);
        System.out.println("// -- TRUSTED IDENTITY ---");
        System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
        System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

        Dime.setTrustedIdentity(trustedIdentity);
        Key intermediateKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
        Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new Capability[] { Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE });
        assertNotNull(intermediateIdentity);
        System.out.println("// -- INTERMEDIATE IDENTITY --");
        System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
        System.out.println("private static final String _encodedIntermediateIdentity = \""+ intermediateIdentity.exportToEncoded() + "\";\n");

        Key issuerKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
        Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[] { Capability.GENERIC, Capability.IDENTIFY });
        assertNotNull(issuerIdentity);
        System.out.println("// -- ISSUER IDENTITY (SENDER) --");
        System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
        System.out.println("public static final String _encodedIssuerIdentity = \""+ issuerIdentity.exportToEncoded() +"\";\n");

        Key audienceKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
        Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[] { Capability.GENERIC, Capability.IDENTIFY });
        assertNotNull(audienceIdentity);
        System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
        System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
        System.out.println("private static String _encodedAudienceIdentity = \""+ audienceIdentity.exportToEncoded() +"\";\n");
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiI0YjExOGE0NS0yMWI1LTRlYzktOGMzNy03NDM0N2UzY2RjNmEiLCJwdWIiOiJEU1ROKzlQTUhLMmViZ0tjQ2cyYWtnazlvWUNNTDJqV3pBdGZhbmFVdzVidDZKcjN2OVNIRGkiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjgzMTAxNVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROKzlMc0Z0MjVxVXhMa251UGM1bm1UcGNHTWNIVWFIWFpYVllQTDZSYlVTUzkxYUFrNk56Yjc5SEU1Rm5DSnlwZWpXckNwSFJRVENLM2YxTGVoNFp4Rkt0M1ptWWJmUyJ9";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiJkNGZkYTljMS1lYmM3LTQ1ODItOGRkYS04ZTA0YjU4YTJjOTMiLCJzdWIiOiJiZDM2ZmQyNy1iMTlkLTRhZWEtODIxZC0wN2VkZTlkNTAzYWQiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiJiZDM2ZmQyNy1iMTlkLTRhZWEtODIxZC0wN2VkZTlkNTAzYWQiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMi0wNS0yN1QwNzoxNzowMC44NzIwNTNaIiwicHViIjoiRFNUTis5UE1ISzJlYmdLY0NnMmFrZ2s5b1lDTUwyald6QXRmYW5hVXc1YnQ2SnIzdjlTSERpIiwiaWF0IjoiMjAyMi0wNS0zMFQwNzoxNzowMC44NzIwNTNaIn0.3vSy48X6SrRI2O4JpT2kxh7MRF0jNSiHlg3ON+mfnvSFwKaxr+E4rkycJqizXeNtto/AerHG326M7AHFWkygBw";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiIxMWE1ZTRmNy0xNWZlLTRkNGItYjExNi1jNGUxODNmYjQzNWMiLCJwdWIiOiJEU1ROK0xHNmZrenlZWDdzNzhLWjNzRmlOb3JVb0NBMkV5SkQ2elZUN1dYdUZFdE1NenppR20iLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg4ODkxNVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROKzdySHdZOGUyRXJncDNnc0V5Zm9wM3VnTDZ4QkZremN2RWhHdmlDalUyZjFuTDVhOEZ2UTdGRjI4R0d5OE14djNFbnJaZGQxcmNESHQ0QTRmbmhINUtFYzl1Sm5DRCJ9";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiI0ZTFjMmM0OS00YWI2LTQ5YzEtYjhhYy0yZWU5NDYzOWVlM2UiLCJzdWIiOiJkY2QzMjA3MC1iOTk2LTRhNTItODBiNi1iNzI4Njc3M2NjMjEiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiaXNzIjoiYmQzNmZkMjctYjE5ZC00YWVhLTgyMWQtMDdlZGU5ZDUwM2FkIiwic3lzIjoiZGltZS1qYXZhLXJlZiIsImV4cCI6IjIwMjctMDUtMjlUMDc6MTc6MDAuODkwNjMxWiIsInB1YiI6IkRTVE4rTEc2Zmt6eVlYN3M3OEtaM3NGaU5vclVvQ0EyRXlKRDZ6VlQ3V1h1RkV0TU16emlHbSIsImlhdCI6IjIwMjItMDUtMzBUMDc6MTc6MDAuODkwNjMxWiJ9.c81T+ChTK7TWj/fC0TMB+N1dwTTEUIoMeAAE5PyGLuK1lm8dgVyYQPNtSxurcvY9rlfMNgzhQAkguSnn8vBuBw";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiI2ODBmMmZiMi1mMGE1LTRkMGUtODNiNy0yMmExOTViMzJjODQiLCJwdWIiOiJEU1ROK0w3WjlnWENOdWF2M2twYnRqRE1XZ200WWRTZXF0TXNOR05XMXEzN0FLbWF0UXFKREwiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5MTc5OFoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROK2FHb0ZSSFQ4Y243eFdjNWdtYUVmRU05MTh2QzJvZ2hGNkpTNGJ5S2k3cmJRVEU0MjR6blpwOXRXU0M0VDVSeDVGZHByMU5XTE5kcnFBMUFFYVhObXB5MTZVa0V4RiJ9";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJ1aWQiOiJjMTAwMDZhZC0zOGJhLTQ2ZDMtYWE1OS02YTYzNGIyMjMzNTMiLCJzdWIiOiI2Y2U0YTdiNy0wNTg3LTQwN2UtOWY5NS05ZDFjZWMxYWZkNzkiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImRjZDMyMDcwLWI5OTYtNGE1Mi04MGI2LWI3Mjg2NzczY2MyMSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoiLCJwdWIiOiJEU1ROK0w3WjlnWENOdWF2M2twYnRqRE1XZ200WWRTZXF0TXNOR05XMXEzN0FLbWF0UXFKREwiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5MzM1NVoifQ.SUQuZXlKMWFXUWlPaUkwWlRGak1tTTBPUzAwWVdJMkxUUTVZekV0WWpoaFl5MHlaV1U1TkRZek9XVmxNMlVpTENKemRXSWlPaUprWTJRek1qQTNNQzFpT1RrMkxUUmhOVEl0T0RCaU5pMWlOekk0TmpjM00yTmpNakVpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWW1Rek5tWmtNamN0WWpFNVpDMDBZV1ZoTFRneU1XUXRNRGRsWkdVNVpEVXdNMkZrSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURVdE1qbFVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSXNJbkIxWWlJNklrUlRWRTRyVEVjMlptdDZlVmxZTjNNM09FdGFNM05HYVU1dmNsVnZRMEV5UlhsS1JEWjZWbFEzVjFoMVJrVjBUVTE2ZW1sSGJTSXNJbWxoZENJNklqSXdNakl0TURVdE16QlVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSjkuYzgxVCtDaFRLN1RXai9mQzBUTUIrTjFkd1RURVVJb01lQUFFNVB5R0x1SzFsbThkZ1Z5WVFQTnRTeHVyY3ZZOXJsZk1OZ3poUUFrZ3VTbm44dkJ1Qnc.vzjmxBAyp2HX3RlWydjGRWsCLOojiXPZQOwEcdcSf+fVq9yWjHkNmJWjsQfxS0El4fDu7WdBidkdNMD7zhgGCw";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiI2ZjM1NmQ1YS1lODBkLTQ2MzktOGYzYi00ZmNmYmE4MWY0MWEiLCJwdWIiOiJEU1ROK05rUVNrdlA5aGhzc2hCQzh5NGVQb0NOZWpXVVc4NzRKNU5yb1pONEJ5MmNncWRrdlYiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5NTUyOFoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROK01iMXViRUVRVm13RGV2ZjFXUlBqRVVram05WVZIMnh0YzZwc2YyY2FVQ0FnM0tXdFdIVG9YTjRyQXFiUHd4TnRURmI2Yzd0ZU04RnRrcUFTYnVvcmlCWUI0OTdLVCJ9";
    private static String _encodedAudienceIdentity = "Di:ID.eyJ1aWQiOiI4YWMyOWViNC01YTc5LTQ4MGEtYmNhMS0yMTViZjZlYWUxMmEiLCJzdWIiOiI2NDk0Njk5MS05MGQ2LTQzYmEtYjYyMy02YTc2MDk5YTJjYjgiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImRjZDMyMDcwLWI5OTYtNGE1Mi04MGI2LWI3Mjg2NzczY2MyMSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA1LTMwVDA3OjE3OjAwLjg5NzgyN1oiLCJwdWIiOiJEU1ROK05rUVNrdlA5aGhzc2hCQzh5NGVQb0NOZWpXVVc4NzRKNU5yb1pONEJ5MmNncWRrdlYiLCJpYXQiOiIyMDIyLTA1LTMwVDA3OjE3OjAwLjg5NzgyN1oifQ.SUQuZXlKMWFXUWlPaUkwWlRGak1tTTBPUzAwWVdJMkxUUTVZekV0WWpoaFl5MHlaV1U1TkRZek9XVmxNMlVpTENKemRXSWlPaUprWTJRek1qQTNNQzFpT1RrMkxUUmhOVEl0T0RCaU5pMWlOekk0TmpjM00yTmpNakVpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWW1Rek5tWmtNamN0WWpFNVpDMDBZV1ZoTFRneU1XUXRNRGRsWkdVNVpEVXdNMkZrSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURVdE1qbFVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSXNJbkIxWWlJNklrUlRWRTRyVEVjMlptdDZlVmxZTjNNM09FdGFNM05HYVU1dmNsVnZRMEV5UlhsS1JEWjZWbFEzVjFoMVJrVjBUVTE2ZW1sSGJTSXNJbWxoZENJNklqSXdNakl0TURVdE16QlVNRGM2TVRjNk1EQXVPRGt3TmpNeFdpSjkuYzgxVCtDaFRLN1RXai9mQzBUTUIrTjFkd1RURVVJb01lQUFFNVB5R0x1SzFsbThkZ1Z5WVFQTnRTeHVyY3ZZOXJsZk1OZ3poUUFrZ3VTbm44dkJ1Qnc.5s809nG0pQnFRnOSsDmSRzs3OLVNGrbgu+8o0HTuBFhw2GyVnYkHzSOIxQClDDZcuky530r/6TBHy78AxroDCg";
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
