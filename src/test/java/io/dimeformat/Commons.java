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

import io.dimeformat.enums.KeyUsage;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;

import static org.junit.jupiter.api.Assertions.*;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "dime-java-ref";
    public static final String PAYLOAD = "Racecar is racecar backwards.";
    public static final String MIMETYPE = "text/plain";
    public static final String CONTEXT = "io.dimeformat.test";
    public static final String SIGN_KEY_CONTEXT = "id-key";

    public static String fullHeaderFor(String itemIdentifier) {
        return Envelope.HEADER + "/" + Dime.VERSION + Dime.DEFAULT_FORMAT +  ":" + itemIdentifier;
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
            Key trustedKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, Dime.VALID_FOR_1_YEAR * 10, new Capability[]{Capability.GENERIC, Capability.ISSUE});
            assertNotNull(trustedIdentity);
            assertFalse(trustedIdentity.isTrusted());
            assertTrue(trustedIdentity.isTrusted(trustedIdentity));
            System.out.println("// -- TRUSTED IDENTITY ---");
            System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

            Dime.setTrustedIdentity(trustedIdentity);
            Key intermediateKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, Dime.VALID_FOR_1_YEAR * 5, new Capability[]{Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE});
            assertNotNull(intermediateIdentity);
            assertTrue(intermediateIdentity.isTrusted());
            System.out.println("// -- INTERMEDIATE IDENTITY --");
            System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
            System.out.println("private static final String _encodedIntermediateIdentity = \"" + intermediateIdentity.exportToEncoded() + "\";\n");

            Key issuerKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(issuerIdentity);
            assertTrue(issuerIdentity.isTrusted());
            System.out.println("// -- ISSUER IDENTITY (SENDER) --");
            System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
            System.out.println("public static final String _encodedIssuerIdentity = \"" + issuerIdentity.exportToEncoded() + "\";\n");

            Key audienceKey = Key.generateKey(List.of(KeyUsage.SIGN), Commons.SIGN_KEY_CONTEXT);
            Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, Dime.VALID_FOR_1_YEAR, new Capability[]{Capability.GENERIC, Capability.IDENTIFY});
            assertNotNull(audienceIdentity);
            assertTrue(audienceIdentity.isTrusted());
            System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
            System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
            System.out.println("private static String _encodedAudienceIdentity = \"" + audienceIdentity.exportToEncoded() + "\";\n");
        } catch (Exception e) {
            fail("Unexpected exception thrown: " + e);
        }
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di/1j:KEY.eyJ1aWQiOiI2MmRiNjcxZC01MzE4LTQ1ODctODg1OC04M2YzM2E4NjY3ZmQiLCJwdWIiOiJEU1ROLnhkNmNkNFZVWGQ0QWdTRUdxRnZtQ3J2TUtKSkVUMUVMcWtjWTVLR1pocU1HRGpCeVYiLCJpYXQiOiIyMDIyLTA2LTExVDExOjIzOjIyLjUxNzQ2N1oiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROLll2a05yaFZ5aE5jZGhUOHhURENkY0dNUjYzbWVpTms5cEF2cGY2SEhKQnFkdUdCaGIxZkU4RVdZM1IxdXlieTRqc3hVR3c0ZGFEcnZ4bzlYY3c5OFUxMlNOaXdqSCJ9";
    private static final String _encodedTrustedIdentity = "Di/1j:ID.eyJ1aWQiOiIzYzYyNDJjOC1jZGVkLTRmYTgtYWU5Yi01ZGIxNTNkNGJlNDciLCJzdWIiOiI0Y2U0NTk4ZS0xOWFkLTQ3OWUtODBiYy1iNjdlY2NkYzY2MmYiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiI0Y2U0NTk4ZS0xOWFkLTQ3OWUtODBiYy1iNjdlY2NkYzY2MmYiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMi0wNi0wOFQxMToyMzoyMi41NTI3NjBaIiwicHViIjoiRFNUTi54ZDZjZDRWVVhkNEFnU0VHcUZ2bUNydk1LSkpFVDFFTHFrY1k1S0daaHFNR0RqQnlWIiwiaWF0IjoiMjAyMi0wNi0xMVQxMToyMzoyMi41NTI3NjBaIn0.M2U1YzQyNmEyZTA3ODIwMy41NjM5MjRhYTY4ZDRmZWM5ZThmYjg2YzYxMmNhOTFiNTAyZmY3ODhiNGU1MTNkZmFjMjVlN2VmOGRiYjFlZTlmYjhkNzE4OTlkYjgzNWU0Yjg2OTU5YmNjOGZjNTdmZjRjODk2ZmI4Y2U5ZmE4MjNhMGExNDEwMzBkNzg1OTEwNw";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di/1j:KEY.eyJ1aWQiOiI4NmQyYzM0Zi0wOTE4LTRhNDUtOTg4My02OTcwN2MyYTgxMmQiLCJwdWIiOiJEU1ROLjI0RXZkUnAycWFud01nNzEyNUptYjZibVZnWEpiMXlWUXB0eTNWN2dhRFFvNEpOalEyIiwiaWF0IjoiMjAyMi0wNi0xMVQxMToyMzoyMi41NjY4NjVaIiwidXNlIjpbInNpZ24iXSwiY3R4IjoiaWQta2V5Iiwia2V5IjoiRFNUTi5KM3BaaUtCa2syanVXR1o4TkxCWkcxa3Q4b3hHUTlMUTdjQkNIcXY5NDVRUXU1d1Z3d29Ma3UzV2E4VDlZQkxSeDhaeDY5eHdXWndidnhndjF1aVZSeGljekJMYW4ifQ";
    private static final String _encodedIntermediateIdentity = "Di/1j:ID.eyJ1aWQiOiI1NjY1ZTBlNC1lMzZkLTQ5NDctYjM3ZC0zNGE0ZjI0OWIwNjkiLCJzdWIiOiIzNjVmNGYzZi1hMGMyLTQ4ZjAtYjkwYi02MDAyMmI3MzRiMTYiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiaXNzIjoiNGNlNDU5OGUtMTlhZC00NzllLTgwYmMtYjY3ZWNjZGM2NjJmIiwic3lzIjoiZGltZS1qYXZhLXJlZiIsImV4cCI6IjIwMjctMDYtMTBUMTE6MjM6MjIuNTY4MzIxWiIsInB1YiI6IkRTVE4uMjRFdmRScDJxYW53TWc3MTI1Sm1iNmJtVmdYSmIxeVZRcHR5M1Y3Z2FEUW80Sk5qUTIiLCJpYXQiOiIyMDIyLTA2LTExVDExOjIzOjIyLjU2ODMyMVoifQ.M2U1YzQyNmEyZTA3ODIwMy43ZDRmODhjYTRiNDM0MzYzNDViMWRlYjg5MjBiOTQ1Yzk3NDIxZjNjMWJhMjYxODc2NDM1Y2I2NWI2MzgyNGQwNDY0YjYyMWUwZDRlMjhkYmU0ZDk5ZWQ0NWE5ZjYzMzEwMzRmMTliYjQ5OGVjYjkxMjNkODY0ZjE3NzkwMTUwZg";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di/1j:KEY.eyJ1aWQiOiIzM2VlMGMwZi0xNTNkLTRiZmYtOTU1Ny01MjU0NTE1ZmIwMzAiLCJwdWIiOiJEU1ROLm1BemVSemNudGk5Q0VITEc2Sjc0WWV6bkJaNzNNemZ0RXdpdkQxa3dKWkdpZndnVjkiLCJpYXQiOiIyMDIyLTA2LTExVDExOjIzOjIyLjU2OTg5MVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROLlhERFhFTVpuTUZ5anhTS3RWakh0Z2pXWmlxZjY3eHdpMlI0cEJ1YUFZV1prOEpaeDZhVGo2N0xhVVNyazlzYUhZM1doS2Z5ZmhDQ3BzcWNtall5OEF6dzlkRVVkcCJ9";
    public static final String _encodedIssuerIdentity = "Di/1j:ID.eyJ1aWQiOiI3ZWYyOTMyNy1kMjc2LTQwZmItOWM3NS1jNzAwZmUxMjc5YWQiLCJzdWIiOiI1MmUxZjA1My03YWY5LTQ2MTktOTkwYi1lZWNlOTQ2NDMyOTUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjM2NWY0ZjNmLWEwYzItNDhmMC1iOTBiLTYwMDIyYjczNGIxNiIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA2LTExVDExOjIzOjIyLjU3MjM0MVoiLCJwdWIiOiJEU1ROLm1BemVSemNudGk5Q0VITEc2Sjc0WWV6bkJaNzNNemZ0RXdpdkQxa3dKWkdpZndnVjkiLCJpYXQiOiIyMDIyLTA2LTExVDExOjIzOjIyLjU3MjM0MVoifQ.SUQuZXlKMWFXUWlPaUkxTmpZMVpUQmxOQzFsTXpaa0xUUTVORGN0WWpNM1pDMHpOR0UwWmpJME9XSXdOamtpTENKemRXSWlPaUl6TmpWbU5HWXpaaTFoTUdNeUxUUTRaakF0WWprd1lpMDJNREF5TW1JM016UmlNVFlpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTkdObE5EVTVPR1V0TVRsaFpDMDBOemxsTFRnd1ltTXRZalkzWldOalpHTTJOakptSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURZdE1UQlVNVEU2TWpNNk1qSXVOVFk0TXpJeFdpSXNJbkIxWWlJNklrUlRWRTR1TWpSRmRtUlNjREp4WVc1M1RXYzNNVEkxU20xaU5tSnRWbWRZU21JeGVWWlJjSFI1TTFZM1oyRkVVVzgwU2s1cVVUSWlMQ0pwWVhRaU9pSXlNREl5TFRBMkxURXhWREV4T2pJek9qSXlMalUyT0RNeU1Wb2lmUS5NMlUxWXpReU5tRXlaVEEzT0RJd015NDNaRFJtT0RoallUUmlORE0wTXpZek5EVmlNV1JsWWpnNU1qQmlPVFExWXprM05ESXhaak5qTVdKaE1qWXhPRGMyTkRNMVkySTJOV0kyTXpneU5HUXdORFkwWWpZeU1XVXdaRFJsTWpoa1ltVTBaRGs1WldRME5XRTVaall6TXpFd016Um1NVGxpWWpRNU9HVmpZamt4TWpOa09EWTBaakUzTnprd01UVXdaZw.ZTI3N2VlYzc5MzMwNThlMi5iNGU2MzFlZGY0YTI5Yzc0M2JiZDE4NjE0NWYzMGQwOTJjZjRjOTJlZjhhNGVmMzEwMzA4ZTU5MDJmZGQ4YjkwNDViNWM3Y2RmNmFmNDQ2NjkxODYzZWQ2ZDY3YjZhNDBjN2VhODA3NDEyNTM4M2U0MDRmNzc5ZjFlOWZmYjIwYQ";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di/1j:KEY.eyJ1aWQiOiI0Y2M3NWU2MC01NDJmLTRjNmYtYmU5My1iYzY0MDMzZGYxZTQiLCJwdWIiOiJEU1ROLjJoQUg2QW9KalJiUzZqaWVDNUFVdnFLczNteURWWGZUaGtaakF1WE5rQ0xNZmJCWEZGIiwiaWF0IjoiMjAyMi0wNi0xMVQxMToyMzoyMi41NzUxMzFaIiwidXNlIjpbInNpZ24iXSwiY3R4IjoiaWQta2V5Iiwia2V5IjoiRFNUTi5ReVpEeXduY1pzUEo3TWoxUm5taFBpOUpIQWlFOVhhMmpGZm9RYUtKTTFFZkJIdVVoVnhqNEZNa3k1eE5wVGVuOXJzaWhqcXN0QVBzRTZDbkdodXY1bkc2cFdyUzUifQ";
    private static String _encodedAudienceIdentity = "Di/1j:ID.eyJ1aWQiOiI1ODM4MzllMy00NzE4LTQ3MTctODBjOS1hODcyOGUxOWY3OGMiLCJzdWIiOiJiZWY3OTdjNy1mNWI3LTQ2OWQtYTAwNC0wZTRjOGY3YTk3ZjEiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjM2NWY0ZjNmLWEwYzItNDhmMC1iOTBiLTYwMDIyYjczNGIxNiIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA2LTExVDExOjIzOjIyLjU3NjUyNVoiLCJwdWIiOiJEU1ROLjJoQUg2QW9KalJiUzZqaWVDNUFVdnFLczNteURWWGZUaGtaakF1WE5rQ0xNZmJCWEZGIiwiaWF0IjoiMjAyMi0wNi0xMVQxMToyMzoyMi41NzY1MjVaIn0.SUQuZXlKMWFXUWlPaUkxTmpZMVpUQmxOQzFsTXpaa0xUUTVORGN0WWpNM1pDMHpOR0UwWmpJME9XSXdOamtpTENKemRXSWlPaUl6TmpWbU5HWXpaaTFoTUdNeUxUUTRaakF0WWprd1lpMDJNREF5TW1JM016UmlNVFlpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTkdObE5EVTVPR1V0TVRsaFpDMDBOemxsTFRnd1ltTXRZalkzWldOalpHTTJOakptSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURZdE1UQlVNVEU2TWpNNk1qSXVOVFk0TXpJeFdpSXNJbkIxWWlJNklrUlRWRTR1TWpSRmRtUlNjREp4WVc1M1RXYzNNVEkxU20xaU5tSnRWbWRZU21JeGVWWlJjSFI1TTFZM1oyRkVVVzgwU2s1cVVUSWlMQ0pwWVhRaU9pSXlNREl5TFRBMkxURXhWREV4T2pJek9qSXlMalUyT0RNeU1Wb2lmUS5NMlUxWXpReU5tRXlaVEEzT0RJd015NDNaRFJtT0RoallUUmlORE0wTXpZek5EVmlNV1JsWWpnNU1qQmlPVFExWXprM05ESXhaak5qTVdKaE1qWXhPRGMyTkRNMVkySTJOV0kyTXpneU5HUXdORFkwWWpZeU1XVXdaRFJsTWpoa1ltVTBaRGs1WldRME5XRTVaall6TXpFd016Um1NVGxpWWpRNU9HVmpZamt4TWpOa09EWTBaakUzTnprd01UVXdaZw.ZTI3N2VlYzc5MzMwNThlMi4xZjc2MjM3ZWMwYjFhZjUwMTk0NjZlNGZiZDkwZjFhYzFmODA4N2U4NWFmMDdhMzI2ODZmMmY5ZjE3NGIyYjFhNGFlYzZlODUzMzNlMjQ0YmRiOGU0MjYzZGY4NTYxY2IzNjMyYjU2YWM5YThiZjA0YTBhM2FkNzNhMTZmMGIwOQ";
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
