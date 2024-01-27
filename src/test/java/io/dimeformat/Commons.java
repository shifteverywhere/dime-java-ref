//
//  Commons.java
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
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
    private static final String _encodedTrustedKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc3MzEwMDVaIiwia2V5IjoiTmFDbC5UU1ZHVUx1bld1M3BQbmQ0MWhoa3Mzc2s2bDBCRGhVcGlvelIveTdVKy9oQ3dETkN0a2crTTc0MTJMK3dMMGNWcm9NVUhRVjh3ZWlRNnJVMW1qUCs5QSIsInB1YiI6Ik5hQ2wuUXNBelFyWklQak8rTmRpL3NDOUhGYTZERkIwRmZNSG9rT3ExTlpvei92USIsInVpZCI6IjEzNzRkNTIwLTM2NzEtNGY2OC1iODg1LTdiZTM3NTViY2Y0OCJ9";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDM0LTAxLTIzVDE0OjQ2OjE1Ljc5MTc4NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MTc4NFoiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLlFzQXpRclpJUGpPK05kaS9zQzlIRmE2REZCMEZmTUhva09xMU5ab3ovdlEiLCJzdWIiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImMyNGFjM2U2LTZlN2MtNDNiOS1iNjUzLTAxY2E3MmM0N2Y2MCJ9.MWZhODZlZWQzYmEzNTczOC41NTkyYzM3Mjc0MGY4MjQxZWMzZTg0ZmMyY2U5YzU5MGY1MjdmNmZlMjhhMjY4YWEzNzM4NWI5MTljMzEzM2ZlMjc5MmYwNjNhOWE5NWYzMmEwODBkOWYyYzk1NjQ0MGQ1NzIxODRhOGEzYzViNDIyYjE1ZjgyNjkwMzNiNmUwNA";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MzUwNzNaIiwia2V5IjoiTmFDbC5VQ216YmV0TVpZa3hvTlRSZFRSblJqRzZGSHhHdnlmRGRqeWdKT0lRTWVDWFl1cDdEeHV1T0dRa2dDN09NKzZnc2RMZkttQ1h0bjVnUUNWMEtTWXY2dyIsInB1YiI6Ik5hQ2wubDJMcWV3OGJyamhrSklBdXpqUHVvTEhTM3lwZ2w3WitZRUFsZENrbUwrcyIsInVpZCI6IjA4ZDE0OWIyLTNiOTUtNGJiZS1hNzFkLTdlY2VjNDg2OTMxMCJ9";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiZXhwIjoiMjAyOS0wMS0yNFQxNDo0NjoxNS43OTU2MzQyWiIsImlhdCI6IjIwMjQtMDEtMjZUMTQ6NDY6MTUuNzk1NjM0MloiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLmwyTHFldzhicmpoa0pJQXV6alB1b0xIUzN5cGdsN1orWUVBbGRDa21MK3MiLCJzdWIiOiIyZjFkMGM0Mi0zYjhhLTQ3YTgtYjM3ZC0wOTE3Yjc2YjY2MzkiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjEyOTA0MGIxLTE5ODAtNDcxMi04NDllLTk4NTc1Mjk5ZGJjZCJ9.MWZhODZlZWQzYmEzNTczOC5kMGUyMjg0M2JkZGM5ZTgwZmY2MzUxZGVmNjg3M2FmOGZhYTE4YWQyMmU0Y2I1Yzc0YWY2NjA3MzllNGEzNmNlMGNmM2FmYjVkYTQ3YzUzZTlmODlhYWI4MDg1OTY0YjM2NWFkMWI5ZDU4MmI3ZDMxMjYxMmRlMmQxZDFmMTIwOQ";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQwMDNaIiwia2V5IjoiTmFDbC5oeHFXRXlTQ2VGV0VvYlFEQm9CNndOdGZvZGtrSDFnbU5uc0pvUDAzVk9BVWNNaUg5Q09sWWdTKzJkWlVDR2drQkNUN0laaDhZTXRmT0dHS1hvK2o4USIsInB1YiI6Ik5hQ2wuRkhESWgvUWpwV0lFdnRuV1ZBaG9KQVFrK3lHWWZHRExYemhoaWw2UG8vRSIsInVpZCI6ImY2OTQ2Njk2LTliYTItNDJiOS1hODIzLWJjZjcyZjZmYjg1NSJ9";
    public static final String _encodedIssuerIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjUtMDEtMjVUMTQ6NDY6MTUuNzk2NDQwMVoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjQ0MDFaIiwiaXNzIjoiMmYxZDBjNDItM2I4YS00N2E4LWIzN2QtMDkxN2I3NmI2NjM5IiwicHViIjoiTmFDbC5GSERJaC9RanBXSUV2dG5XVkFob0pBUWsreUdZZkdETFh6aGhpbDZQby9FIiwic3ViIjoiMzBiYjEwZGItY2QzNS00ZjNkLWIyNmEtYjdkZjBjNTgyNzljIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIxYjYyYmY0ZC05Yjk3LTQyOGMtYWJkNC04NzI1MGM1Y2MzNmMifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU9TMHdNUzB5TkZReE5EbzBOam94TlM0M09UVTJNelF5V2lJc0ltbGhkQ0k2SWpJd01qUXRNREV0TWpaVU1UUTZORFk2TVRVdU56azFOak0wTWxvaUxDSnBjM01pT2lJMk5UUTVPR1l4Tnkxak16STFMVFEzT1dNdFltWTVZeTA0TldFMFptSmxPR0V3WWpBaUxDSndkV0lpT2lKT1lVTnNMbXd5VEhGbGR6aGljbXBvYTBwSlFYVjZhbEIxYjB4SVV6TjVjR2RzTjFvcldVVkJiR1JEYTIxTUszTWlMQ0p6ZFdJaU9pSXlaakZrTUdNME1pMHpZamhoTFRRM1lUZ3RZak0zWkMwd09URTNZamMyWWpZMk16a2lMQ0p6ZVhNaU9pSnBieTVrYVcxbFptOXliV0YwTG5KbFppSXNJblZwWkNJNklqRXlPVEEwTUdJeExURTVPREF0TkRjeE1pMDRORGxsTFRrNE5UYzFNams1WkdKalpDSjkuTVdaaE9EWmxaV1F6WW1Fek5UY3pPQzVrTUdVeU1qZzBNMkprWkdNNVpUZ3dabVkyTXpVeFpHVm1OamczTTJGbU9HWmhZVEU0WVdReU1tVTBZMkkxWXpjMFlXWTJOakEzTXpsbE5HRXpObU5sTUdObU0yRm1ZalZrWVRRM1l6VXpaVGxtT0RsaFlXSTRNRGcxT1RZMFlqTTJOV0ZrTVdJNVpEVTRNbUkzWkRNeE1qWXhNbVJsTW1ReFpERm1NVEl3T1E.YzBlZWJhNGRiZTZhYjNjNy5mMWNlMzllNmZmOWM4NmUzNmU0Mzk2ZjkxNmMyYjcxMGJjNzY1MThjNTc2NmJiYjUwNzZmMGUxMGVlNTVjZjhhMGZlYWIxODgzZjM5NDYyZWMzMmU2ZTE0NDE4YWFhOWZmYjNjOTYzMDViMDdkN2FjMTk3ODQ4NjQ4ZjYxZDEwMQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjU0OVoiLCJrZXkiOiJOYUNsLkVDUW9YTkRvaEp4MlhNTUVQVTZPWEQ4bVZTclE3eE0wa3M0UDBiQ1MxRDA5enhRYUppY2RSM0tEUit0S2V2UTdvYk43TUl3OVNIUFphbXRXWVQyTjFnIiwicHViIjoiTmFDbC5QYzhVR2lZbkhVZHlnMGZyU25yME82R3plekNNUFVoejJXcHJWbUU5amRZIiwidWlkIjoiYTZhNzAyYzItODQ1ZS00NGVlLThlZWMtODgyOGQzYTQ2ZDc0In0";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjUtMDEtMjVUMTQ6NDY6MTUuNzk2NTc2NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5NjU3NjRaIiwiaXNzIjoiMmYxZDBjNDItM2I4YS00N2E4LWIzN2QtMDkxN2I3NmI2NjM5IiwicHViIjoiTmFDbC5QYzhVR2lZbkhVZHlnMGZyU25yME82R3plekNNUFVoejJXcHJWbUU5amRZIiwic3ViIjoiOTc3Yjc1ZTctYmFlMC00YmMzLTkxMzYtZTNkY2M0YzEwODk5Iiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiI1MzI3YTY3Mi1iYzk1LTQ2MWYtYmRkZS0yZDgwY2UxZTM5MmYifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU9TMHdNUzB5TkZReE5EbzBOam94TlM0M09UVTJNelF5V2lJc0ltbGhkQ0k2SWpJd01qUXRNREV0TWpaVU1UUTZORFk2TVRVdU56azFOak0wTWxvaUxDSnBjM01pT2lJMk5UUTVPR1l4Tnkxak16STFMVFEzT1dNdFltWTVZeTA0TldFMFptSmxPR0V3WWpBaUxDSndkV0lpT2lKT1lVTnNMbXd5VEhGbGR6aGljbXBvYTBwSlFYVjZhbEIxYjB4SVV6TjVjR2RzTjFvcldVVkJiR1JEYTIxTUszTWlMQ0p6ZFdJaU9pSXlaakZrTUdNME1pMHpZamhoTFRRM1lUZ3RZak0zWkMwd09URTNZamMyWWpZMk16a2lMQ0p6ZVhNaU9pSnBieTVrYVcxbFptOXliV0YwTG5KbFppSXNJblZwWkNJNklqRXlPVEEwTUdJeExURTVPREF0TkRjeE1pMDRORGxsTFRrNE5UYzFNams1WkdKalpDSjkuTVdaaE9EWmxaV1F6WW1Fek5UY3pPQzVrTUdVeU1qZzBNMkprWkdNNVpUZ3dabVkyTXpVeFpHVm1OamczTTJGbU9HWmhZVEU0WVdReU1tVTBZMkkxWXpjMFlXWTJOakEzTXpsbE5HRXpObU5sTUdObU0yRm1ZalZrWVRRM1l6VXpaVGxtT0RsaFlXSTRNRGcxT1RZMFlqTTJOV0ZrTVdJNVpEVTRNbUkzWkRNeE1qWXhNbVJsTW1ReFpERm1NVEl3T1E.YzBlZWJhNGRiZTZhYjNjNy44YzcxMjdiNzQ5ZTBlOGQ5NzdmYzZiNGFjYTcxNjc2N2I2MjYwMmVkOTQ1ODBmNjA5NDkzZmM3ZDg2M2M2MjdjMjk2NDA4YjFhM2E4YjViYzMzYTk2NmMzMDM1MTY4MTdhMTU2MDdlMzgxNzU2MzAyMzc1NzA3MGMyOTJhOTEwNw";
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
