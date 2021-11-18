//
//  Commons.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "dime-java-ref";

    public static Key getTrustedKey() {
        if (Commons._trustedKey == null) { Commons._trustedKey = Commons.importFromEncoded(Commons._encodedTrustedKey); }
        return Commons._trustedKey;
    };
    
    public static Identity getTrustedIdentity() {
        if (Commons._trustedIdentity == null) { Commons._trustedIdentity = Commons.importFromEncoded(Commons._encodedTrustedIdentity); }
        return Commons._trustedIdentity;
    };

    public static Key getIntermediateKey() {
        if (Commons._intermediateKey == null) { Commons._intermediateKey = Commons.importFromEncoded(Commons._encodedIntermediateKey); }
        return Commons._intermediateKey;
    };
    
    public static Identity getIntermediateIdentity() {
        if (Commons._intermediateIdentity == null) { Commons._intermediateIdentity = Commons.importFromEncoded(Commons._encodedIntermediateIdentity); }
        return Commons._intermediateIdentity;
    };

    public static Key getIssuerKey() {
        if (Commons._issuerKey == null) { Commons._issuerKey = Commons.importFromEncoded(Commons._encodedIssuerKey); }
        return Commons._issuerKey;
    };
    
    public static Identity getIssuerIdentity() {
        if (Commons._issuerIdentity == null) { Commons._issuerIdentity = Commons.importFromEncoded(Commons._encodedIssuerIdentity); }
        return Commons._issuerIdentity;
    };

    public static Key getAudienceKey() {
        if (Commons._audienceKey == null) { Commons._audienceKey = Commons.importFromEncoded(Commons._encodedAudienceKey); }
        return Commons._audienceKey;
    };
    
    public static Identity getAudienceIdentity() {
        if (Commons._audienceIdentity == null) { Commons._audienceIdentity = Commons.importFromEncoded(Commons._encodedAudienceIdentity); }
        return Commons._audienceIdentity;
    };

    /// TESTS ///

    @Test
    public void generateCommons() {
        System.out.println("// -- TRUSTED IDENTITY ---");
        System.out.println("private static final String _encodedTrustedKey = \"Di:KEY\";");
        System.out.println("private static final String _encodedTrustedIdentity = \"Di:ID\";\n");

        System.out.println("// -- INTERMEDIATE IDENTITY --");
        System.out.println("private static final String _encodedIntermediateKey = \"Di:KEY\";");
        System.out.println("private static final String _encodedIntermediateIdentity = \"Di:ID\";\n");

        System.out.println("// -- ISSUER IDENTITY (SENDER) --");
        System.out.println("private static final String _encodedIssuerKey = \"Di:KEY\";");
        System.out.println("private static String _encodedIssuerIdentity = \"Di:ID\";\n");

        System.out.println("// -- AUDIENCE IDENTITY (RECEIVER) --");
        System.out.println("private static final String _encodedAudienceKey = \"Di:KEY\";");
        System.out.println("private static String _encodedAudienceIdentity = \"Di:ID\";\n");
    }

    /// PRIVATE ///

    // -- TRUSTED IDENTITY ---
    private static final String _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiIwMmQwNDk0OS1mOTc5LTQ0ZTMtYWZmZi1iNmIxYzIwMGI5YmMiLCJwdWIiOiIyVERYZG9OdWNRRTJZM2tXY2hhNEJ1YUxVdWg4YW1UYmV2djZhNUVlZlltc1pNbjJYSFRQcFBFNlYiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjQ2OjU3LjAxNTgwOVoiLCJrZXkiOiJTMjFUWlNMOTJFQWZWajVjY0NQYmdUSnNVdTdEY21vSEdKQjRkb0s2ckJyNjJZVnJKaGZUNVBGUzh0S3Y2aEJkY1ZLZ3hwZFZWZ01SYjd2dThESlBuRlBWYlRUbU5lNWlSWVhmIn0";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJ1aWQiOiIxOTczYWVjYy03MTkwLTQyZDgtODQ1OC1jYmE4NDdhMjY5MDgiLCJzdWIiOiJkMzllMGIwMS0xZmU4LTRiNjYtYjIwOC1iYTEzOGI1ZTM4ZDAiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJpc3MiOiJkMzllMGIwMS0xZmU4LTRiNjYtYjIwOC1iYTEzOGI1ZTM4ZDAiLCJzeXMiOiJkaW1lLWphdmEtcmVmIiwiZXhwIjoiMjAzMS0xMS0xNlQxNDo0Njo1Ny4wMzQyMTJaIiwicHViIjoiMlREWGRvTnVjUUUyWTNrV2NoYTRCdWFMVXVoOGFtVGJldnY2YTVFZWZZbXNaTW4yWEhUUHBQRTZWIiwiaWF0IjoiMjAyMS0xMS0xOFQxNDo0Njo1Ny4wMzQyMTJaIn0.N1FjS4FQr82ozhYNVz+U6Dk0wL0la06YGV5AtmY2xOgrQdyQki1eQY/zKb09m95OCKsegS915Sq+qM71WqK/DA";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiI3NDUxYzhiYi1kYzUxLTRlYTYtOTRlMy1lMTc5ZjQ3YzQwMDQiLCJwdWIiOiIyVERYZG9OdXVIZzJ1NjJmemRHeTR4RkRCS3BnY014TmJLUEM0YUtudG5UclFwR29peWpNTUFEUmYiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjQ4OjA4LjA3NTM5OVoiLCJrZXkiOiJTMjFUWlNMVEMyY2FNRzk4S2p3SkJUWW84Vk1UNWYzUGZVU24xcFdzVHppNFBDZzdYb2JEUjhuV3JQR0d2YlNaeUEzNTM3WUtYOGVxemR1NWs2SzFOemNuR3Q3dHl0WE5DdnpaIn0";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJ1aWQiOiI5NzNjMzVhMC0wYmUwLTRjNTEtOGM0Zi01ZjY3ZmMwMDc4MjQiLCJzdWIiOiI2ODg4MGZmMy1mZTk0LTRmZjAtOTE0OC0wMGI5ODA4Mzg4NzciLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5IiwiaXNzdWUiXSwiaXNzIjoiZDM5ZTBiMDEtMWZlOC00YjY2LWIyMDgtYmExMzhiNWUzOGQwIiwic3lzIjoiZGltZS1qYXZhLXJlZiIsImV4cCI6IjIwMjYtMTEtMTdUMTQ6NDg6MTYuNTk0Njg4WiIsInB1YiI6IjJURFhkb051dUhnMnU2MmZ6ZEd5NHhGREJLcGdjTXhOYktQQzRhS250blRyUXBHb2l5ak1NQURSZiIsImlhdCI6IjIwMjEtMTEtMThUMTQ6NDg6MTYuNTk0Njg4WiJ9.DYQPu6StKgii80boEx+npHmxhran4pff0VxE5eNlOwOTi8S48QlaA3oTNwo1SJWBqOOUE+VFt+1WD5pYBnHOAg";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiI4ZjEyNDgzMS01NzBlLTQyMmUtYjNiMS00NzlhNzI3ZTY2ZGEiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg1NzI2M1oiLCJrZXkiOiJTMjFUWlNMS1B2MVhDajdNVGN6V3ZkQVRUU3M5ek4xc3VKNUFEWnlZaldFcnZBaG1WZEduUDYxYm1HRlVodUFmcUg0UkQ1eGdTTjZaY2RhR1prMno4aXhSRnJVU05ZQmhzQnZyIn0";
    private static String _encodedIssuerIdentity = "Di:ID.eyJ1aWQiOiI2YWU2OGE3MC0xN2Y2LTQ1MDQtOWFlMy1jNWJhOWUyZDQ4ZmIiLCJzdWIiOiIwYWE1NjEzMy03OGIwLTRkZDktOTI4ZC01ZDdmZjlkYTU0NDUiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloiLCJwdWIiOiIyVERYZG9OdXN2czJjOGdHb1I0b1pjNzZVeDU0c0E4M2J3ZTd3eXJyVjZSUllya25aTDkzblFGZmsiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjUxOjM2Ljg2MjM3NloifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.yoSmBKB/YAWQ68gh//utH8G2szGr1VkRlyvR7kdY5Iy2fHtuL5ynA+0ZsehLv/fk6H8poA0yj/qNFIKLOohtAw";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiIxYzEwZjM5ZC0yY2RjLTQ0ODEtYmY1ZS0wNTBlMzA2ZWY0YWQiLCJwdWIiOiIyVERYZG9OdmZ2QjVrVThhR1RUMlNpdmtSN05EbnJtVlZNTmYzU1A0QXpYOVFiOXVBQmhHRWhMUWkiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjU0OjI3LjUwODI0MFoiLCJrZXkiOiJTMjFUWlNMODE3SHluaEs3YUJ6U3hnWW91NDltSmlxUDREazR4OVpjaVE1WEcxdERLQkxCcWZxcGZqTnRhZk13a3VLM0FhYnBuR0t0Z2M5OHZIWnVnSEJuTjlOcHl6c1UxcGtyIn0";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJ1aWQiOiJhMDE4ZDQ4Yi0wYjcwLTRlMjQtOWIyMC0wYzQ0ZjQ3NGMyNDgiLCJzdWIiOiJhNjkwMjE4NC0yYmEwLTRiYTAtYWI5MS1jYTc3ZGE3ZDA1ZDMiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImlzcyI6IjY4ODgwZmYzLWZlOTQtNGZmMC05MTQ4LTAwYjk4MDgzODg3NyIsInN5cyI6ImRpbWUtamF2YS1yZWYiLCJleHAiOiIyMDIyLTExLTE4VDE0OjU0OjI3LjUxMzI5MFoiLCJwdWIiOiIyVERYZG9OdmZ2QjVrVThhR1RUMlNpdmtSN05EbnJtVlZNTmYzU1A0QXpYOVFiOXVBQmhHRWhMUWkiLCJpYXQiOiIyMDIxLTExLTE4VDE0OjU0OjI3LjUxMzI5MFoifQ.SUQuZXlKMWFXUWlPaUk1TnpOak16VmhNQzB3WW1Vd0xUUmpOVEV0T0dNMFppMDFaalkzWm1Nd01EYzRNalFpTENKemRXSWlPaUkyT0RnNE1HWm1NeTFtWlRrMExUUm1aakF0T1RFME9DMHdNR0k1T0RBNE16ZzROemNpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aWFYTnpJam9pWkRNNVpUQmlNREV0TVdabE9DMDBZalkyTFdJeU1EZ3RZbUV4TXpoaU5XVXpPR1F3SWl3aWMzbHpJam9pWkdsdFpTMXFZWFpoTFhKbFppSXNJbVY0Y0NJNklqSXdNall0TVRFdE1UZFVNVFE2TkRnNk1UWXVOVGswTmpnNFdpSXNJbkIxWWlJNklqSlVSRmhrYjA1MWRVaG5NblUyTW1aNlpFZDVOSGhHUkVKTGNHZGpUWGhPWWt0UVF6UmhTMjUwYmxSeVVYQkhiMmw1YWsxTlFVUlNaaUlzSW1saGRDSTZJakl3TWpFdE1URXRNVGhVTVRRNk5EZzZNVFl1TlRrME5qZzRXaUo5LkRZUVB1NlN0S2dpaTgwYm9FeCtucEhteGhyYW40cGZmMFZ4RTVlTmxPd09UaThTNDhRbGFBM29UTndvMVNKV0JxT09VRStWRnQrMVdENXBZQm5IT0Fn.1k/T9SNUneSkHOfWKNoGm/7IYvuvcn1DiHh99TyJTARp8+XvMLI7tpQa8YAQwTd//JxSOAFjaknCc9HTHW3vDw";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;

    private static <T extends Item> T importFromEncoded(String encoded) {
        try {
            T item = Item.importFromEncoded(encoded);
            return item;
        } catch (Exception e) {
            throw new RuntimeException(); // Should not happen
        }
    }

}
