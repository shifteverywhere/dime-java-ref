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
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "io.dimeformat.ref";
    public static final String PAYLOAD = "Racecar is racecar backwards.";
    public static final String MIMETYPE = "text/plain";
    public static final String COMMON_NAME = "DiME";
    public static final String CONTEXT = "test-context";
    public static final String SIGN_KEY_CONTEXT = "id-key";
    public static final String ISSUER_URL = "https://example.dimeformat.io";

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
            assertFalse(trustedIdentity.verify().isValid());
            assertTrue(trustedIdentity.verify(trustedIdentity).isValid());

            System.out.println("// -- TRUSTED IDENTITY ---");
            System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

            Dime.keyRing.put(trustedIdentity);
            Key intermediateKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY, IdentityCapability.ISSUE});
            assertNotNull(intermediateIdentity);
            assertTrue(intermediateIdentity.verify().isValid());
            System.out.println("// -- INTERMEDIATE IDENTITY --");
            System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedIntermediateIdentity = \"" + intermediateIdentity.exportToEncoded() + "\";\n");

            Key issuerKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY});
            assertNotNull(issuerIdentity);
            assertTrue(issuerIdentity.verify().isValid());
            System.out.println("// -- ISSUER IDENTITY (SENDER) --");
            System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
            System.out.println("public static final String _encodedIssuerIdentity = \"" + issuerIdentity.exportToEncoded() + "\";\n");

            Key audienceKey = Key.generateKey(List.of(KeyCapability.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new IdentityCapability[]{IdentityCapability.GENERIC, IdentityCapability.IDENTIFY});
            assertNotNull(audienceIdentity);
            assertTrue(audienceIdentity.verify().isValid());
            System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
            System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedAudienceIdentity = \"" + audienceIdentity.exportToEncoded() + "\";\n");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    /// PROTECTED ///

    static Identity generateIdentity(Key subjectKey, Key issuerKey, Identity issuerIdentity, long validFor, IdentityCapability[] capabilities) {
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

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA4Ljk4Nzc3N1oiLCJrZXkiOiJEU0MudEQ4WGZEc0wvSGFPVnRQd0pqZ0tNSnBReGJPTGk4TVlMeFJxRkZGTnVGV1lkRWZkZjlmd3ducmRXRTlYYmhocUlyQlIvUXdZeFNQTFNrM3FJZWhQaEEiLCJwdWIiOiJEU0MubUhSSDNYL1g4TUo2M1ZoUFYyNFlhaUt3VWYwTUdNVWp5MHBONmlIb1Q0USIsInVpZCI6IjFjMzhkN2RkLTFhMTUtNDY4ZS1iNDQ3LTJjNjRhMGZkZGIxZiJ9";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTEwLTIxVDIyOjA0OjA5LjAyMzIyNFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjAyMzIyNFoiLCJpc3MiOiIxNzNmNTJkNi0yNjdjLTQ4OTUtODQ3My0yMTcwMTYwZjM4NmMiLCJwdWIiOiJEU0MubUhSSDNYL1g4TUo2M1ZoUFYyNFlhaUt3VWYwTUdNVWp5MHBONmlIb1Q0USIsInN1YiI6IjE3M2Y1MmQ2LTI2N2MtNDg5NS04NDczLTIxNzAxNjBmMzg2YyIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiN2JmNzljN2UtZDQxMi00MWQ1LTg3N2ItOTgyNzI4Y2FmZTIyIn0.MzJkMTQzYzJkMDYyMzA2Yi5hZmJhYjcwY2MyZDUyNzAxMTMzZjFlM2RlNzAzMGIzZDFjODQ1YjcyOGI5NjRkODRkMmUwOTcxNTU1MGVkNWFlODMxZjljZTdjYjhjMDMxYTZlNTFjOGFlZmQ5ZTBkOGNiMTVlNzgxMzc0NTljMzE2ZmFlZDgwNzFkZGM0MjEwZg";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjA0MDY2M1oiLCJrZXkiOiJEU0MuN1ZOMmI2ZjBueHF1YlNVOTU1UHVNZW5MdFY2dTlsdFFyMG92VUcwQ0wwUmZoYjlTOUl2VWFwTmo1OENIY3NWd01ZcjNiT3cvYWdoakVDVmN1YTJNK1EiLCJwdWIiOiJEU0MuWDRXL1V2U0wxR3FUWStmQWgzTEZjREdLOTJ6c1Ayb0lZeEFsWExtdGpQayIsInVpZCI6ImE1OWFlMDgwLTkxNDUtNDRjMC05NTliLTAzNjZjZGE3ZDdkMyJ9";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyNy0xMC0yM1QyMjowNDowOS4wNDE4ODVaIiwiaWF0IjoiMjAyMi0xMC0yNFQyMjowNDowOS4wNDE4ODVaIiwiaXNzIjoiMTczZjUyZDYtMjY3Yy00ODk1LTg0NzMtMjE3MDE2MGYzODZjIiwicHViIjoiRFNDLlg0Vy9VdlNMMUdxVFkrZkFoM0xGY0RHSzkyenNQMm9JWXhBbFhMbXRqUGsiLCJzdWIiOiIwZWNiZWIxYi03MGI0LTQ0ZWItYmE1MS05ZGE1YTk2ZDkzN2MiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImU0M2QzNWIwLWRhZDYtNGMyMi05MGIxLTJkNmZhYjkxZTliZSJ9.MzJkMTQzYzJkMDYyMzA2Yi5mOTI3NzkxNmM0YjMyMmM5MTQ1MjUyYjJhOGE2MDFhOWJiYzhlMTcxMWI3MDAzZjc0Y2I4NjU1M2Y0YWUzNzAwYzNmYjg1ODYwYjIxNGI2ZDhjZjU3ZjU2MzhhOThjMGJhYjAzOTZhMjFlMDA1MjNkMWY2MDUxZThhOWIxNTQwYg";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjA0NDc4N1oiLCJrZXkiOiJEU0MubXZ2c0pUN0ptNzJ6Uk1MSDdsdnpvdUdaS1NHNzFQbTZGUEI1bVVOejJwL2VlZk1YODVVdFpXNkd5a3JaenBCYVMyMHJnZm9KY0JmN2UybjFJbWM4NWciLCJwdWIiOiJEU0MuM25uekYvT1ZMV1Z1aHNwSzJjNlFXa3R0SzRINkNYQVgrM3RwOVNKblBPWSIsInVpZCI6ImJkMTkzYzJlLTIwOGQtNDJkYi1hZTFjLTYwYWQzYjE2MmI0MyJ9";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MDQ6MDkuMDQ1MjIxWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MDQ6MDkuMDQ1MjIxWiIsImlzcyI6IjBlY2JlYjFiLTcwYjQtNDRlYi1iYTUxLTlkYTVhOTZkOTM3YyIsInB1YiI6IkRTQy4zbm56Ri9PVkxXVnVoc3BLMmM2UVdrdHRLNEg2Q1hBWCszdHA5U0puUE9ZIiwic3ViIjoiNTcxODk4NDAtMjBhYS00ZWVhLTk4NzgtYjkyM2E3N2ZiMmViIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIyMGYwMmFlZi1lM2JiLTQwNTctOTA5OC0zZDg5M2U0ZjI0ZDQifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFYTnpJam9pTVRjelpqVXlaRFl0TWpZM1l5MDBPRGsxTFRnME56TXRNakUzTURFMk1HWXpPRFpqSWl3aWNIVmlJam9pUkZORExsZzBWeTlWZGxOTU1VZHhWRmtyWmtGb00weEdZMFJIU3preWVuTlFNbTlKV1hoQmJGaE1iWFJxVUdzaUxDSnpkV0lpT2lJd1pXTmlaV0l4WWkwM01HSTBMVFEwWldJdFltRTFNUzA1WkdFMVlUazJaRGt6TjJNaUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SW1VME0yUXpOV0l3TFdSaFpEWXROR015TWkwNU1HSXhMVEprTm1aaFlqa3haVGxpWlNKOS5NekprTVRRell6SmtNRFl5TXpBMllpNW1PVEkzTnpreE5tTTBZak15TW1NNU1UUTFNalV5WWpKaE9HRTJNREZoT1dKaVl6aGxNVGN4TVdJM01EQXpaamMwWTJJNE5qVTFNMlkwWVdVek56QXdZek5tWWpnMU9EWXdZakl4TkdJMlpEaGpaalUzWmpVMk16aGhPVGhqTUdKaFlqQXpPVFpoTWpGbE1EQTFNak5rTVdZMk1EVXhaVGhoT1dJeE5UUXdZZw.NTAyZmE0Y2Q1MWFiNTZkMi40MGZjZGRlYTZlNWVlMGNlMjc1Mjk2MmFjYzFkZGNlYjg3OGQxMWIzN2YxMjIzODY2MjRjNTFhNTJmYmRhYTZiMzYyYjQ2MjlmYmUyNDdkYzJjMGRlZGY0ZGM0OGVmNGE5NzdhNTE0MGU1YjFkZGFiNWJiZjU2Mzg4MjRkNzQwZA";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjA0OjA5LjA0ODYwM1oiLCJrZXkiOiJEU0MuUHVjZEZVckZsQ1hOVEJFOWRhZEl5WlFkcmVmRVVhT1Q5OTNhZFZ3aENYZE9zWnRacE51YndkS2FTalpZS1RLMGszang1R3hYK3FNZW5aTnBGNlBheGciLCJwdWIiOiJEU0MuVHJHYldhVGJtOEhTbWtvMldDa3l0Sk40OGVSc1YvcWpIcDJUYVJlajJzWSIsInVpZCI6IjE3N2Y0ZGZkLWQ5YjEtNDdkZi05MTlmLTczNjFlODdjMDI2NSJ9";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6MDQ6MDkuMDUxMTIyWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6MDQ6MDkuMDUxMTIyWiIsImlzcyI6IjBlY2JlYjFiLTcwYjQtNDRlYi1iYTUxLTlkYTVhOTZkOTM3YyIsInB1YiI6IkRTQy5UckdiV2FUYm04SFNta28yV0NreXRKTjQ4ZVJzVi9xakhwMlRhUmVqMnNZIiwic3ViIjoiMWE5Njc4N2QtYWVmMy00MmE4LThjNjctMWY3OTk5MzQ2Y2JmIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiJiM2RlNTQ0Ny03ZDljLTQ0YTMtYmRjMi03NmVkNzc2MDMzMWMifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3dORG93T1M0d05ERTRPRFZhSWl3aWFYTnpJam9pTVRjelpqVXlaRFl0TWpZM1l5MDBPRGsxTFRnME56TXRNakUzTURFMk1HWXpPRFpqSWl3aWNIVmlJam9pUkZORExsZzBWeTlWZGxOTU1VZHhWRmtyWmtGb00weEdZMFJIU3preWVuTlFNbTlKV1hoQmJGaE1iWFJxVUdzaUxDSnpkV0lpT2lJd1pXTmlaV0l4WWkwM01HSTBMVFEwWldJdFltRTFNUzA1WkdFMVlUazJaRGt6TjJNaUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SW1VME0yUXpOV0l3TFdSaFpEWXROR015TWkwNU1HSXhMVEprTm1aaFlqa3haVGxpWlNKOS5NekprTVRRell6SmtNRFl5TXpBMllpNW1PVEkzTnpreE5tTTBZak15TW1NNU1UUTFNalV5WWpKaE9HRTJNREZoT1dKaVl6aGxNVGN4TVdJM01EQXpaamMwWTJJNE5qVTFNMlkwWVdVek56QXdZek5tWWpnMU9EWXdZakl4TkdJMlpEaGpaalUzWmpVMk16aGhPVGhqTUdKaFlqQXpPVFpoTWpGbE1EQTFNak5rTVdZMk1EVXhaVGhoT1dJeE5UUXdZZw.NTAyZmE0Y2Q1MWFiNTZkMi5lNzcxZTM4ZDE4N2YxNTYyYzI5NTU1OGJjNDZkOTM4MzJlNjE4Zjc5ZDZmOGJmZDFhYWJiNTI0N2Q3Y2NkZDY4NDU0MmU5Mzk1ZjgxNmE0MjIzNGE1OWViODExZDU4YjcxMjQzNzk0MmJmNTNkMTZmYjVjYTViNjg0ODZiYjkwZQ";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;

    private static <T extends Item> T importFromEncoded(String encoded) {
        try {
            return Item.importFromEncoded(encoded);
        } catch (Exception e) {
            throw new RuntimeException(); // Should not happen
        }
    }

}
