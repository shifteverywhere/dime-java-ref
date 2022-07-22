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

import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;

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

    /// TESTS ///

    @Test
    public void generateCommons() {
        try {
            Dime.setTrustedIdentity(null);
            Key trustedKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, Dime.VALID_FOR_1_YEAR * 10, new Capability[]{Capability.GENERIC, Capability.ISSUE});
            assertNotNull(trustedIdentity);
            assertFalse(trustedIdentity.isTrusted());
            assertTrue(trustedIdentity.isTrusted(trustedIdentity));
            System.out.println("// -- TRUSTED IDENTITY ---");
            System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

            Dime.setTrustedIdentity(trustedIdentity);
            Key intermediateKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new Capability[]{Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE});
            assertNotNull(intermediateIdentity);
            assertTrue(intermediateIdentity.isTrusted());
            System.out.println("// -- INTERMEDIATE IDENTITY --");
            System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedIntermediateIdentity = \"" + intermediateIdentity.exportToEncoded() + "\";\n");

            Key issuerKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(issuerIdentity);
            assertTrue(issuerIdentity.isTrusted());
            System.out.println("// -- ISSUER IDENTITY (SENDER) --");
            System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
            System.out.println("public static final String _encodedIssuerIdentity = \"" + issuerIdentity.exportToEncoded() + "\";\n");

            Key audienceKey = Key.generateKey(List.of(Key.Use.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(audienceIdentity);
            assertTrue(audienceIdentity.isTrusted());
            System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
            System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedAudienceIdentity = \"" + audienceIdentity.exportToEncoded() + "\";\n");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA2LTI5VDIwOjU2OjA3LjAyODI5MVoiLCJrZXkiOiJEU1ROLjdRRjRQeTRBUnlhNmY3TktqZkVNaWI3cjlBS2dFM2tzUzgzOGZSREhLWE5pendOUUUxa3RzQWpvUjZnU1g5M0JrcDdENGVEemhNTWNFQ0E5YWtyQW5tcWhHZFFXNiIsInB1YiI6IkRTVE4uc2FUaVJpNURDNWZRS3g1V3dMWjNxdFZlWjZwUEF4QmlpcW9EcUZUbTZGTGV0V3pjNSIsInVpZCI6ImY5N2E4NTY2LWU1MGMtNGQ3OS04NmEyLWI5YjUxNjlkNTk2YyIsInVzZSI6WyJzaWduIl19";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTA2LTI2VDIwOjU2OjA3LjA2ODEwMVoiLCJpYXQiOiIyMDIyLTA2LTI5VDIwOjU2OjA3LjA2ODEwMVoiLCJpc3MiOiIzYzM2ZjhiZC0yOWNhLTQ2ZTAtOGY0Ni1jYmNjODhmMWYxMWQiLCJwdWIiOiJEU1ROLnNhVGlSaTVEQzVmUUt4NVd3TFozcXRWZVo2cFBBeEJpaXFvRHFGVG02RkxldFd6YzUiLCJzdWIiOiIzYzM2ZjhiZC0yOWNhLTQ2ZTAtOGY0Ni1jYmNjODhmMWYxMWQiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjU4YzU1MzRmLWM0MWItNGUyOS1hNTQ3LTFhZTBiNDVhOTNlNyJ9.NTcxODQ5ODRjMDg2YmE1My41MGFmYjIyYWYyZTlkODhiMmI0OWE4MGQ1NzRmZDU0NWVjOTEwM2JiMzE3MTZkYzM4M2E0NjhmMmZiMjYwMzgxNjdhOTUzZjhkNTZkYTkzZWNkYzNmODE3OTBlOWJjZDEzM2E3NGRlNjYwYzJlMzQ2YzgyNTc3MDE2ZTc5ZjUwMA";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA2LTI5VDIwOjU2OjA3LjA4NjU1MVoiLCJrZXkiOiJEU1ROLjVmUDJxQkViUzFqYzJreVFSOEFKTkpFeEI4cmdvRUpYS1RiODNXV01qQ2VISmdMOGpRc2lhRUtYajZ4TW14RlBpcjg5aGd0Y0pGQkFWcWtiZlIzMTdUZWJrRUpyOCIsInB1YiI6IkRTVE4uMjZlM1B3Ukh5SFpwS2hkWjRWTGZaN0ZRY0ZNNGtMeURNNTg2Yk5pVW9UUzdua1o0R3MiLCJ1aWQiOiJiYTg1ZjBlOC1hYWZiLTQ4NDktODg0Ni00MjY3ZTNmNzFlM2IiLCJ1c2UiOlsic2lnbiJdfQ";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0wNi0yOFQyMDo1NjowNy4wODgxNjFaIiwiaWF0IjoiMjAyMi0wNi0yOVQyMDo1NjowNy4wODgxNjFaIiwiaXNzIjoiM2MzNmY4YmQtMjljYS00NmUwLThmNDYtY2JjYzg4ZjFmMTFkIiwicHViIjoiRFNUTi4yNmUzUHdSSHlIWnBLaGRaNFZMZlo3RlFjRk00a0x5RE01ODZiTmlVb1RTN25rWjRHcyIsInN1YiI6IjJjYmZmZGUxLTlmM2QtNGYzOC05MzliLTJlMWZlNzQ4ZDhkYyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiOTgwOGJkYzUtZmI3Ni00MzVlLWI1MDUtMzVjNzZiZTc4Nzk1In0.NTcxODQ5ODRjMDg2YmE1My5mZTk3Y2QxNzMxODg2NjA0OTQ2ODM4NzEzOWNmYTUyYWM4MjBkMjliYzBmYTlmMDk3NGNlYTRmOTRmN2YzZDE4NjI2NmMwZjg0YjE4NGZhNzY2ODhiZTEwMDc4NTJlYWZhZWMzNjA4MzNiYTBiOTc3YzIzOWZmNzc0MWJjZTkwNQ";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA2LTI5VDIwOjU2OjA3LjA4OTcyNloiLCJrZXkiOiJEU1ROLlc2UHNwUzhnb3BqQ2V5ZjNSS3lvMTQ4NmExZlZGSDFxSzZzTER4d0pveVQ1YW83ckFuSmtUbWdEaXJzb1lITjZHUWVRcDNZTEdnNnhNVzdORkg4UVVZa29nOFo4aCIsInB1YiI6IkRTVE4uMm9hekFyY3ptdjVRcjZ4dGsxU2RkU3J4N3QzNEVKSHEyMjg1WmZqaVlHYlRHRVdwZmgiLCJ1aWQiOiJmNzQ4OWE4OS0zYmIzLTQwMjAtOWJiMS03MmEwYmQyZDExNmIiLCJ1c2UiOlsic2lnbiJdfQ";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDYtMjlUMjA6NTY6MDcuMDkyMTE3WiIsImlhdCI6IjIwMjItMDYtMjlUMjA6NTY6MDcuMDkyMTE3WiIsImlzcyI6IjJjYmZmZGUxLTlmM2QtNGYzOC05MzliLTJlMWZlNzQ4ZDhkYyIsInB1YiI6IkRTVE4uMm9hekFyY3ptdjVRcjZ4dGsxU2RkU3J4N3QzNEVKSHEyMjg1WmZqaVlHYlRHRVdwZmgiLCJzdWIiOiIyZmMyMTA4NC1iNWVkLTQ5MjAtODlmMy03MTZiNGZmMmJmM2IiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjgxZDJlNjgwLWIxNTktNDg5My05YmNiLTI1OTMyZDZiZWM0OCJ9.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdOaTB5T0ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFXRjBJam9pTWpBeU1pMHdOaTB5T1ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFYTnpJam9pTTJNek5tWTRZbVF0TWpsallTMDBObVV3TFRobU5EWXRZMkpqWXpnNFpqRm1NVEZrSWl3aWNIVmlJam9pUkZOVVRpNHlObVV6VUhkU1NIbElXbkJMYUdSYU5GWk1abG8zUmxGalJrMDBhMHg1UkUwMU9EWmlUbWxWYjFSVE4yNXJXalJIY3lJc0luTjFZaUk2SWpKalltWm1aR1V4TFRsbU0yUXROR1l6T0MwNU16bGlMVEpsTVdabE56UTRaRGhrWXlJc0luTjVjeUk2SW1sdkxtUnBiV1ZtYjNKdFlYUXVjbVZtSWl3aWRXbGtJam9pT1Rnd09HSmtZelV0Wm1JM05pMDBNelZsTFdJMU1EVXRNelZqTnpaaVpUYzROemsxSW4wLk5UY3hPRFE1T0RSak1EZzJZbUUxTXk1bVpUazNZMlF4TnpNeE9EZzJOakEwT1RRMk9ETTROekV6T1dObVlUVXlZV000TWpCa01qbGlZekJtWVRsbU1EazNOR05sWVRSbU9UUm1OMll6WkRFNE5qSTJObU13WmpnMFlqRTROR1poTnpZMk9EaGlaVEV3TURjNE5USmxZV1poWldNek5qQTRNek5pWVRCaU9UYzNZekl6T1dabU56YzBNV0pqWlRrd05R.OTk1NzQ5NzUxNGI2NGI0Ny4zYjNmZmE1NjYyNmEwMzRjNTk1MjUxZTNiYTU0ZGQ4YzFhYThlODhmMDU1OWQ5ZmNmMzRhNmQ1OTU3ZjI0NWVkMDRkZmViM2MzYjBjN2E0YmJiZThjYzgzN2U5YjM3OTg0ZmJlMjVkMjBlMzhhYjQzYmNkZTgyMzFjYzlkNTEwZQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTA2LTI5VDIwOjU2OjA3LjA5NTM3NVoiLCJrZXkiOiJEU1ROLjl6d1VmcVVpeWJZcHh0ZzlMeURVTktTek5SUzhhUmpZMVp4TEJYNFk5a3ZDdVIzSjJ2UEJ4RERYNlNNRnQycmliU0pTajM2b3hVY040dFBVZ0pMQUNhU0p5WDh3RSIsInB1YiI6IkRTVE4uc3dFc3NCZEVvRzFYTTFROW9hRE5Zb1Y4a1d2a1I4THFTSDJNOFJXNDVvUVZWU0pLMyIsInVpZCI6ImYzNGUyMmM2LTI4OGMtNGU1Ni04OWUxLWU0MDdjMTQ0MjUxOSIsInVzZSI6WyJzaWduIl19";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMDYtMjlUMjA6NTY6MDcuMDk3MDQ3WiIsImlhdCI6IjIwMjItMDYtMjlUMjA6NTY6MDcuMDk3MDQ3WiIsImlzcyI6IjJjYmZmZGUxLTlmM2QtNGYzOC05MzliLTJlMWZlNzQ4ZDhkYyIsInB1YiI6IkRTVE4uc3dFc3NCZEVvRzFYTTFROW9hRE5Zb1Y4a1d2a1I4THFTSDJNOFJXNDVvUVZWU0pLMyIsInN1YiI6ImJmYjQ1NWI4LTNhNzQtNGJhZi1hZGQxLWU0MTA3NmQ1ZmZlNCIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiZTc4MzU5OWQtMDBiMi00NWUzLTk5MjctZDNhNDI0YjZkZjA5In0.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdOaTB5T0ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFXRjBJam9pTWpBeU1pMHdOaTB5T1ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFYTnpJam9pTTJNek5tWTRZbVF0TWpsallTMDBObVV3TFRobU5EWXRZMkpqWXpnNFpqRm1NVEZrSWl3aWNIVmlJam9pUkZOVVRpNHlObVV6VUhkU1NIbElXbkJMYUdSYU5GWk1abG8zUmxGalJrMDBhMHg1UkUwMU9EWmlUbWxWYjFSVE4yNXJXalJIY3lJc0luTjFZaUk2SWpKalltWm1aR1V4TFRsbU0yUXROR1l6T0MwNU16bGlMVEpsTVdabE56UTRaRGhrWXlJc0luTjVjeUk2SW1sdkxtUnBiV1ZtYjNKdFlYUXVjbVZtSWl3aWRXbGtJam9pT1Rnd09HSmtZelV0Wm1JM05pMDBNelZsTFdJMU1EVXRNelZqTnpaaVpUYzROemsxSW4wLk5UY3hPRFE1T0RSak1EZzJZbUUxTXk1bVpUazNZMlF4TnpNeE9EZzJOakEwT1RRMk9ETTROekV6T1dObVlUVXlZV000TWpCa01qbGlZekJtWVRsbU1EazNOR05sWVRSbU9UUm1OMll6WkRFNE5qSTJObU13WmpnMFlqRTROR1poTnpZMk9EaGlaVEV3TURjNE5USmxZV1poWldNek5qQTRNek5pWVRCaU9UYzNZekl6T1dabU56YzBNV0pqWlRrd05R.OTk1NzQ5NzUxNGI2NGI0Ny4zN2VkZDIzNjQ4OGY3ZjEyNDIzNzhiMjEwODQ0ZTNjMGNhYjJjZjg5ZDk1MWE5Nzg1N2VlNDFmYTM3YjlkZmVjNjhiZjViNWI4MzA4OGUyNWM3NjFhYjExMDVlYTEwM2M5ZDk5YTI3NzVjMjk0YWU5MjQwNGJiNTMyZGJjYjcwMA";
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
