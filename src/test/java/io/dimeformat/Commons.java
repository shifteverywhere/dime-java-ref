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
    private static final String _encodedTrustedKey = "Di/1j:KEY.eyJ1aWQiOiIzYzEzMTVlYy1hNjAyLTQyNGUtODRmNy1lMGY1YWE5NGEwMmMiLCJwdWIiOiJEU1ROLnlGQW5VYzViS2VzQUNqUXp2N0Y5OGloUGdHQTQ5WGhmbkE3a2dRbzh6MTFWbTlmUzgiLCJpYXQiOiIyMDIyLTA2LTEwVDE4OjU4OjE2LjUzOTgyNVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROLjZQeTJhR3k2WEttNGFCdDc1dFFrUVVqRmNnbW5zdXZWRnNOZXkzekVVdmV4cWd1N0VyemdBWVVoZjhSQ1NiaXM5RFB5d3d5Sm52RjVlVGFFZ2JtZjFMSzQ3WWJQRyJ9";
    private static final String _encodedTrustedIdentity = "Di/1j:ID.eyJ1aWQiOiJlNjYwZDgyZi0zZGM5LTQxZDMtOWQ3Zi1jYWYzNjkwODRiYmYiLCJzdWIiOiI5Mzc2MjU0YS01M2MyLTQ3MDktODI1Ny0yYTNhNGM5MWU3MzUiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiI5Mzc2MjU0YS01M2MyLTQ3MDktODI1Ny0yYTNhNGM5MWU3MzUiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMi0wNi0wN1QxODo1ODoxNi41NzY5MzVaIiwicHViIjoiRFNUTi55RkFuVWM1Yktlc0FDalF6djdGOThpaFBnR0E0OVhoZm5BN2tnUW84ejExVm05ZlM4IiwiaWF0IjoiMjAyMi0wNi0xMFQxODo1ODoxNi41NzY5MzVaIn0.Xo4GBxERocDQ1SFuyazCKrNtM4ksZvkeo/RNeb62aqHJH7qdnLSLHS75hN4nMHmGJz0vAbXVM+/v3ye7QKaDDQ";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di/1j:KEY.eyJ1aWQiOiIzMjU2OTUwZS01YzFlLTQ2MWYtODBjNC1hMWU5YTBkN2Y3ZjYiLCJwdWIiOiJEU1ROLnE4Y0tLb1Nka2MzbVoxMjc2bVRXNlJqakNaWWV1akRTTlpHbWdjZkRwa05ka0ZkdHYiLCJpYXQiOiIyMDIyLTA2LTEwVDE4OjU4OjE2LjU5Mjg1MVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROLkE0dkxoQUNvQXBSWmM3ejd0S3gzaEVRQVRLQ0diVkhhY3dXbjM2WEhrTjRObXpjeTI3VlA5NHplVm5QOEsxbVQ3cVZTVDZwRmtyNEJTU3h2aU1CVWVORW9ydDZyTiJ9";
    private static final String _encodedIntermediateIdentity = "Di/1j:ID.eyJ1aWQiOiI3NTgwOGI0NS02M2FkLTQ4OTctYjFlNC1jZTVkNjVhYjA5YTQiLCJzdWIiOiJkNWZmOTAzZC05MDRhLTQ3MjEtOWUxMS1iMmI1YzZhYzkwNDAiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiaXNzIjoiOTM3NjI1NGEtNTNjMi00NzA5LTgyNTctMmEzYTRjOTFlNzM1Iiwic3lzIjoiZGltZS1qYXZhLXJlZiIsImV4cCI6IjIwMjctMDYtMDlUMTg6NTg6MTYuNTk0NjE0WiIsInB1YiI6IkRTVE4ucThjS0tvU2RrYzNtWjEyNzZtVFc2UmpqQ1pZZXVqRFNOWkdtZ2NmRHBrTmRrRmR0diIsImlhdCI6IjIwMjItMDYtMTBUMTg6NTg6MTYuNTk0NjE0WiJ9.++TSRyRM9ngYyK91aNiuSq3cUAZcIsaYKdmNUVFzNa+2uvxchShmqFl/NM6ysLQ9sEKaKtgMuZg8j2kcYQc2DQ";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di/1j:KEY.eyJ1aWQiOiIyYjYwZmZiNC05MThjLTRiZDktYTgxOS1iYWE0ZDU1OWZiMjQiLCJwdWIiOiJEU1ROLjJTWFp5RW8yc3dITHBXZ3ljSlhWNnFzcG03eEFMMXJud0dvRExvc3ZiVTNVckFVanNpIiwiaWF0IjoiMjAyMi0wNi0xMFQxODo1ODoxNi41OTYwMThaIiwidXNlIjpbInNpZ24iXSwiY3R4IjoiaWQta2V5Iiwia2V5IjoiRFNUTi5KOExuaU5UaFd2d3VhN2U1ZmdqemR3WlFnUGR5RDJUaWp0Tko0aFBjZ1BtaUY3WDc3dmJTUG5RR0dkNXRrVTN4YnNMUUhuSzRVTWh4b29zU1VWeWZ6MzZ0UGc4WmQifQ";
    public static final String _encodedIssuerIdentity = "Di/1j:ID.eyJ1aWQiOiJmNGQwYTI4YS02NzkyLTQ3OTEtYTMwYy05Mjc4MDI3YmIzMzkiLCJzdWIiOiI4ZWYyODljMy0wYzJjLTRlZjktYjNlMy00NTQ4MDExYTFhMWUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImQ1ZmY5MDNkLTkwNGEtNDcyMS05ZTExLWIyYjVjNmFjOTA0MCIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA2LTEwVDE4OjU4OjE2LjU5NzUzN1oiLCJwdWIiOiJEU1ROLjJTWFp5RW8yc3dITHBXZ3ljSlhWNnFzcG03eEFMMXJud0dvRExvc3ZiVTNVckFVanNpIiwiaWF0IjoiMjAyMi0wNi0xMFQxODo1ODoxNi41OTc1MzdaIn0.SUQuZXlKMWFXUWlPaUkzTlRnd09HSTBOUzAyTTJGa0xUUTRPVGN0WWpGbE5DMWpaVFZrTmpWaFlqQTVZVFFpTENKemRXSWlPaUprTldabU9UQXpaQzA1TURSaExUUTNNakV0T1dVeE1TMWlNbUkxWXpaaFl6a3dOREFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pT1RNM05qSTFOR0V0TlROak1pMDBOekE1TFRneU5UY3RNbUV6WVRSak9URmxOek0xSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURZdE1EbFVNVGc2TlRnNk1UWXVOVGswTmpFMFdpSXNJbkIxWWlJNklrUlRWRTR1Y1RoalMwdHZVMlJyWXpOdFdqRXlOelp0VkZjMlVtcHFRMXBaWlhWcVJGTk9Xa2R0WjJObVJIQnJUbVJyUm1SMGRpSXNJbWxoZENJNklqSXdNakl0TURZdE1UQlVNVGc2TlRnNk1UWXVOVGswTmpFMFdpSjkuKytUU1J5Uk05bmdZeUs5MWFOaXVTcTNjVUFaY0lzYVlLZG1OVVZGek5hKzJ1dnhjaFNobXFGbC9OTTZ5c0xROXNFS2FLdGdNdVpnOGoya2NZUWMyRFE./GDBNuLnvKXlQMthlwKNVYUez6Xqe1VBlTZeF4mXGigDgpk+FSKmyioyHvxXQaSvAVK6ryI4nhVfxFm70u3wBA";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di/1j:KEY.eyJ1aWQiOiJjNmNmODZkMy0xZDRmLTQxMzUtYTk2NS0yMjEzMjA4YTNmNGQiLCJwdWIiOiJEU1ROLjhwQWRCdEE0V1BWaHpXanRWQTRnRlRVZFhpVWI2Y0Z1NXBpb0V2dXdVdmVnU1lNYnkiLCJpYXQiOiIyMDIyLTA2LTEwVDE4OjU4OjE2LjYwMDI3NVoiLCJ1c2UiOlsic2lnbiJdLCJjdHgiOiJpZC1rZXkiLCJrZXkiOiJEU1ROLkVyejRqU0JkOG8yQTlkclFLS1VTRlJSS2F2RWVrbThOM04yMnBnak5qZW9jaVpzeU55b1FFN1dxeWdhemlVcTNpOXZWZTg1ZllCNFpHRDU0V3Jyc0JHcHRKc0pFbyJ9";
    private static String _encodedAudienceIdentity = "Di/1j:ID.eyJ1aWQiOiI4YTMyZjhjZC0zNzQ0LTQ0MmUtOWVjZi0xMjM3ZGYwMGQ4MGYiLCJzdWIiOiI5ZjUwMzQ3YS1iYmU5LTQ0ODUtOTY3NC01OGJmZDAwYmI2NDQiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImQ1ZmY5MDNkLTkwNGEtNDcyMS05ZTExLWIyYjVjNmFjOTA0MCIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIzLTA2LTEwVDE4OjU4OjE2LjYwMjU5NloiLCJwdWIiOiJEU1ROLjhwQWRCdEE0V1BWaHpXanRWQTRnRlRVZFhpVWI2Y0Z1NXBpb0V2dXdVdmVnU1lNYnkiLCJpYXQiOiIyMDIyLTA2LTEwVDE4OjU4OjE2LjYwMjU5NloifQ.SUQuZXlKMWFXUWlPaUkzTlRnd09HSTBOUzAyTTJGa0xUUTRPVGN0WWpGbE5DMWpaVFZrTmpWaFlqQTVZVFFpTENKemRXSWlPaUprTldabU9UQXpaQzA1TURSaExUUTNNakV0T1dVeE1TMWlNbUkxWXpaaFl6a3dOREFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pT1RNM05qSTFOR0V0TlROak1pMDBOekE1TFRneU5UY3RNbUV6WVRSak9URmxOek0xSWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNamN0TURZdE1EbFVNVGc2TlRnNk1UWXVOVGswTmpFMFdpSXNJbkIxWWlJNklrUlRWRTR1Y1RoalMwdHZVMlJyWXpOdFdqRXlOelp0VkZjMlVtcHFRMXBaWlhWcVJGTk9Xa2R0WjJObVJIQnJUbVJyUm1SMGRpSXNJbWxoZENJNklqSXdNakl0TURZdE1UQlVNVGc2TlRnNk1UWXVOVGswTmpFMFdpSjkuKytUU1J5Uk05bmdZeUs5MWFOaXVTcTNjVUFaY0lzYVlLZG1OVVZGek5hKzJ1dnhjaFNobXFGbC9OTTZ5c0xROXNFS2FLdGdNdVpnOGoya2NZUWMyRFE.NPMrvpZvwZN+koZglVA5BrQrcpFy7Ooms02+fpiPc5DMtxGVNsXn/6dWz+dFG4KuAw2f1NTnNiwFOntkxkXVDw";
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
