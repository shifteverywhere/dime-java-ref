//
//  Commons.java
//  Di:ME - Data Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2022 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import io.dimeformat.enums.Capability;
import io.dimeformat.enums.KeyType;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "dime-java-ref";
    public static final String PAYLOAD = "Racecar is racecar backwards.";
    public static final String MIMETYPE = "text/plain";
    public static final String CONTEXT = "io.dimeformat.test";

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
        Key trustedKey = Key.generateKey(KeyType.IDENTITY, "id-key");
        Identity trustedIdentity = Commons.generateIdentity(trustedKey, trustedKey, null, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, new Capability[] { Capability.GENERIC, Capability.ISSUE });
        assertNotNull(trustedIdentity);
        System.out.println("// -- TRUSTED IDENTITY ---");
        System.out.println("private static final String _encodedTrustedKey = \"" + trustedKey.exportToEncoded() + "\";");
        System.out.println("private static final String _encodedTrustedIdentity = \"" + trustedIdentity.exportToEncoded() + "\";\n");

        Dime.setTrustedIdentity(trustedIdentity);
        Key intermediateKey = Key.generateKey(KeyType.IDENTITY, "id-key");
        Identity intermediateIdentity = Commons.generateIdentity(intermediateKey, trustedKey, trustedIdentity, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, new Capability[] { Capability.GENERIC, Capability.IDENTIFY, Capability.ISSUE });
        assertNotNull(intermediateIdentity);
        System.out.println("// -- INTERMEDIATE IDENTITY --");
        System.out.println("private static final String _encodedIntermediateKey = \"" + intermediateKey.exportToEncoded() + "\";");
        System.out.println("private static final String _encodedIntermediateIdentity = \""+ intermediateIdentity.exportToEncoded() + "\";\n");

        Key issuerKey = Key.generateKey(KeyType.IDENTITY, "id-key");
        Identity issuerIdentity = Commons.generateIdentity(issuerKey, intermediateKey, intermediateIdentity, IdentityIssuingRequest.VALID_FOR_1_YEAR, new Capability[] { Capability.GENERIC, Capability.IDENTIFY });
        assertNotNull(issuerIdentity);
        System.out.println("// -- ISSUER IDENTITY (SENDER) --");
        System.out.println("private static final String _encodedIssuerKey = \"" + issuerKey.exportToEncoded() + "\";");
        System.out.println("public static String _encodedIssuerIdentity = \""+ issuerIdentity.exportToEncoded() +"\";\n");

        Key audienceKey = Key.generateKey(KeyType.IDENTITY, "id-key");
        Identity audienceIdentity = Commons.generateIdentity(audienceKey, intermediateKey, intermediateIdentity, IdentityIssuingRequest.VALID_FOR_1_YEAR, new Capability[] { Capability.GENERIC, Capability.IDENTIFY });
        assertNotNull(audienceIdentity);
        System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
        System.out.println("private static final String _encodedAudienceKey = \"" + audienceKey.exportToEncoded() + "\";");
        System.out.println("private static String _encodedAudienceIdentity = \""+ audienceIdentity.exportToEncoded() +"\";\n");

        Key serverKey = Key.generateKey(KeyType.EXCHANGE, "x-server");
        Key clientKey = Key.generateKey(KeyType.EXCHANGE, "x-client");
        System.out.println("x-server:" + serverKey.exportToEncoded());
        System.out.println("x-client:" + clientKey.exportToEncoded());
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiJmZDdkODdhMy0xZDVmLTRkZDUtOGVmMS0wMGZlMjNmMzk0NzMiLCJwdWIiOiIyVERYZG9OdlpSV2hVRlh6ZVBqbmdqeWltWUxRc0VZWXd6RXpkMmU2Mmp4d0Y0cmR1NDN2aXhtREoiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc0NDk1MVoiLCJrZXkiOiJTMjFUWlNMRFR5TFdXaHRNYllkWUNjNXFWOVg0UnpVWXFQMTJIR29nVnpSWHJ0dGc3cFlKekwxbXh6THpTV2puU1Z6RzJ4YzJmcDJad0FKWFc0NzhtY0JHcEdnQ2ZGaTl4YXViIn0";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiI0MDViZDZhOC0wM2JmLTRjNDctOWNiYS0xNmNhODM5OGI1YzgiLCJzdWIiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiIxZmNkNWY4OC00YTc1LTQ3OTktYmQ0OC0yNWI2ZWEwNjQwNTMiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMS0xMS0xOFQxMjoxMTowMi43NjEwMDdaIiwicHViIjoiMlREWGRvTnZaUldoVUZYemVQam5nanlpbVlMUXNFWVl3ekV6ZDJlNjJqeHdGNHJkdTQzdml4bURKIiwiaWF0IjoiMjAyMS0xMS0yMFQxMjoxMTowMi43NjEwMDdaIn0.KE3hbTLB7+BzzEeGSFyauy2PMgXBIYpGqRFZ2n+xQQsAOxC45xYgeFvILtqLeVYKA8T5lcQvZdyuiHBPVMpxBw";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiI1Y2FiMzA0Yi0wMzI1LTQ0NWQtODM3ZS1mNzA3ZDBjYmNkMTUiLCJwdWIiOiIyVERYZG9OdkQ4Y0M5dXhTYjRKRkhyazFmUEhXd3FxU0NVSkdlOFZnVkZzYVc1S3FGMndrWGJVUE4iLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2Mjk0OVoiLCJrZXkiOiJTMjFUWlNMOHBQeEVVaVRad2NQVEVuR2tjZjF1UEx3ckRmeDRYTHNSazZWZmZkYTNqVkhQOHBGRlNITlZBQkNwOWl0SDhHMXRvcDl3b1BGYm5ONXlqYmZSODZrRFBRU1VEUERlIn0";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiIyM2Q5ZWRkZi1mYzhkLTRjMzctYmM5Mi03MTQzNDU0YTI0ZDUiLCJzdWIiOiJiZDI4ZGI4Zi0xMzYyLTRhZmQtYWVkNy00Y2EzOWY2NTk3NWUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiaXNzIjoiMWZjZDVmODgtNGE3NS00Nzk5LWJkNDgtMjViNmVhMDY0MDUzIiwic3lzIjoiZGltZS1qYXZhLXJlZiIsImV4cCI6IjIwMjYtMTEtMTlUMTI6MTE6MDIuNzYzNjUyWiIsInB1YiI6IjJURFhkb052RDhjQzl1eFNiNEpGSHJrMWZQSFd3cXFTQ1VKR2U4VmdWRnNhVzVLcUYyd2tYYlVQTiIsImlhdCI6IjIwMjEtMTEtMjBUMTI6MTE6MDIuNzYzNjUyWiJ9.56v5LyX8jtKCsty7gm6Ns2cY+bMIX4pq44g80SEpu61vBIsRVzQ1NdV9CPWhtStvD3ww7Ma8X7BVo1lk26c2Dg";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiJiMTZjYTg3My0yYmQ4LTQ4ZWItOTQyNC1iMGEwODkzY2NhNjUiLCJwdWIiOiIyVERYZG9OdzF3WlF0ZVU1MzI1czZSbVJYVnBUa1lXdlR1RXpSMWpOZFZ2WWpFUjZiNmJZYUR6dEYiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NDI3MloiLCJrZXkiOiJTMjFUWlNMMUttZVl6VlkxdzViWXJxa1lMaXoxRkx1Z2UyRllVcGZLUVg2M2R0V1E4YUxaNVhza0hZVE5vV3NWN3p6UWJkUFFlZ29RU0xoVzV0aEp1czZZWlhGTjhLUzVnNGdXIn0";
    public static String _encodedIssuerIdentity = "Di:ID.eyJ1aWQiOiIyYTdkNDJhMy02YjQ1LTRhNGEtYmIzZC1lYzk0ZWMzNzlmMWYiLCJzdWIiOiJiZTRhZjVmMy1lODM4LTQ3MzItYTBmYy1mZmEyYzMyOGVhMTAiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImJkMjhkYjhmLTEzNjItNGFmZC1hZWQ3LTRjYTM5ZjY1OTc1ZSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTIwVDEyOjExOjAyLjc2NTI1OVoiLCJwdWIiOiIyVERYZG9OdzF3WlF0ZVU1MzI1czZSbVJYVnBUa1lXdlR1RXpSMWpOZFZ2WWpFUjZiNmJZYUR6dEYiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NTI1OVoifQ.SUQuZXlKMWFXUWlPaUl5TTJRNVpXUmtaaTFtWXpoa0xUUmpNemN0WW1NNU1pMDNNVFF6TkRVMFlUSTBaRFVpTENKemRXSWlPaUppWkRJNFpHSTRaaTB4TXpZeUxUUmhabVF0WVdWa055MDBZMkV6T1dZMk5UazNOV1VpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTVdaalpEVm1PRGd0TkdFM05TMDBOems1TFdKa05EZ3RNalZpTm1WaE1EWTBNRFV6SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UbFVNVEk2TVRFNk1ESXVOell6TmpVeVdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MlJEaGpRemwxZUZOaU5FcEdTSEpyTVdaUVNGZDNjWEZUUTFWS1IyVTRWbWRXUm5OaFZ6VkxjVVl5ZDJ0WVlsVlFUaUlzSW1saGRDSTZJakl3TWpFdE1URXRNakJVTVRJNk1URTZNREl1TnpZek5qVXlXaUo5LjU2djVMeVg4anRLQ3N0eTdnbTZOczJjWStiTUlYNHBxNDRnODBTRXB1NjF2QklzUlZ6UTFOZFY5Q1BXaHRTdHZEM3d3N01hOFg3QlZvMWxrMjZjMkRn.7H3RwTTeDcI3pGMIWMPbAjpDnCN2O91JG4lKu3JJbxlLNwTbgTB/03xrwi28wl0iMReJ4zUPc3cCqbymAlxwAw";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiJiNTMzZDcwNy1mZjg3LTRmMDItOTA5MC05OTgyZTZhYTAwMjEiLCJwdWIiOiIyVERYZG9OdW5qZGhyYVhTZXI5M3RuanZGR3lEbVNIRzFpQnd4MnNqWW9TUFpoeVlkcE02WVRuUVoiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2NjE5MloiLCJrZXkiOiJTMjFUWlNMQWYyVTh1RXlUTVphd0FoOHZMNG1Za3JBc050dGlUcG1DelVyajg2NkVrOURCckFtZWJYV0VtcEpwckplN1ZpcWN1Q3JXQ21wb252SE0zZ3c3YXRZbllZRXI5cDg2In0";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJ1aWQiOiJmZDVkYWM2MC0zYjUwLTQ1ZWUtOGI0My1lMWM2YzRiY2NiZjciLCJzdWIiOiIxMjFmM2QzMi1mODU3LTQ5OWYtOTg4YS0wNzY0ODQ4YTdiNjMiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6ImJkMjhkYjhmLTEzNjItNGFmZC1hZWQ3LTRjYTM5ZjY1OTc1ZSIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTIwVDEyOjExOjAyLjc2Njc4NloiLCJwdWIiOiIyVERYZG9OdW5qZGhyYVhTZXI5M3RuanZGR3lEbVNIRzFpQnd4MnNqWW9TUFpoeVlkcE02WVRuUVoiLCJpYXQiOiIyMDIxLTExLTIwVDEyOjExOjAyLjc2Njc4NloifQ.SUQuZXlKMWFXUWlPaUl5TTJRNVpXUmtaaTFtWXpoa0xUUmpNemN0WW1NNU1pMDNNVFF6TkRVMFlUSTBaRFVpTENKemRXSWlPaUppWkRJNFpHSTRaaTB4TXpZeUxUUmhabVF0WVdWa055MDBZMkV6T1dZMk5UazNOV1VpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pTVdaalpEVm1PRGd0TkdFM05TMDBOems1TFdKa05EZ3RNalZpTm1WaE1EWTBNRFV6SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UbFVNVEk2TVRFNk1ESXVOell6TmpVeVdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MlJEaGpRemwxZUZOaU5FcEdTSEpyTVdaUVNGZDNjWEZUUTFWS1IyVTRWbWRXUm5OaFZ6VkxjVVl5ZDJ0WVlsVlFUaUlzSW1saGRDSTZJakl3TWpFdE1URXRNakJVTVRJNk1URTZNREl1TnpZek5qVXlXaUo5LjU2djVMeVg4anRLQ3N0eTdnbTZOczJjWStiTUlYNHBxNDRnODBTRXB1NjF2QklzUlZ6UTFOZFY5Q1BXaHRTdHZEM3d3N01hOFg3QlZvMWxrMjZjMkRn.kdtTRVPwUz1GVAFIZ7Qon261qh1IrpWVQnCZPztHU49g2PDgIC6nd8gbhBQVU1P8Wfq75PF7IpPEsGHPa1WdBA";
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
