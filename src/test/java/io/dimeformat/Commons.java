package io.dimeformat;

import org.junit.jupiter.api.Test;

public class Commons {

    /// PUBLIC ///

    public static final String SYSTEM_NAME = "dime-java-ref";

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
    private static final String _encodedTrustedKey = "Di:KEY.eyJ1aWQiOiI3NzgwMzIwMy1lZGFiLTRhMTktOTBlYS0wYzJiNWExYjI0MTEiLCJpYXQiOiIyMDIxLTA5LTA2VDA4OjA1OjIzLjMwMDEyNFoiLCJrZXkiOiIxaEVrRW9uYzk0Y2dURmtWeHpra3hBYWVDS3lvdEdMZ0FOZktHVWI3R1RNZXVIWk44N3ZGVSIsInB1YiI6IjFoUEpFakE5RHdZWEU5eEFtTlZzdXV2U1NtanBXZXNyck5zN3pqWTduYXFCMm1WMmdFVzlRIn0";
    private static final String _encodedTrustedIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiM2JmNDkwYmItYTI4My00NmQzLTkxOTQtN2VkOTJkNzY3YWM3Iiwic3ViIjoiYWU2MmRmNzItMzQ5MS00M2EwLWFhOTAtMTkzZTRhMTQwM2Q4IiwiaXNzIjoiYWU2MmRmNzItMzQ5MS00M2EwLWFhOTAtMTkzZTRhMTQwM2Q4IiwiaWF0IjoiMjAyMS0wOS0wNlQwODowNToyMy4zMzA2MDJaIiwiZXhwIjoiMjAzMS0wOS0wNFQwODowNToyMy4zMzA2MDJaIiwicHViIjoiMWhQSkVqQTlEd1lYRTl4QW1OVnN1dXZTU21qcFdlc3JyTnM3empZN25hcUIybVYyZ0VXOVEiLCJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdfQ.AaJ//PCSMiYNevP/RFfgjZ3GvrlQLHEOV+8PWgHW4ADaM72vo60tbpo5HTUk60jBUU3cdmkENG/1N5rk/Pht3A8";
    private static Key _trustedKey;
    private static Identity _trustedIdentity;

    // -- INTERMEDIATE IDENTITY --
    private static final String _encodedIntermediateKey = "Di:KEY.eyJ1aWQiOiIwNzM5NzRkZC1kOWYyLTQyNDAtOGZjMy03ZjgzY2M3M2UwOTciLCJpYXQiOiIyMDIxLTA5LTA2VDA4OjA2OjQ1LjcyNDMwNVoiLCJrZXkiOiIxaEVpeGR6ZzhtVXdWVG9tMmIxa0ZHTkROdUFaZFh1NkhLdWFoeUtweFVvdW1HWnJCQmtBaCIsInB1YiI6IjFoUEtZSmR6NnQxNU53Nzkzd0hOZFRpWWhFdWszVmlUeWVqdEV6VktxUTF0Z1drYVJMbzl4In0";
    private static final String _encodedIntermediateIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMTYxYzQ3ZGItMTc2OC00NGI0LThhOTAtZGRhOWFiZTdiYmNjIiwic3ViIjoiOTEyZWQ5YmEtYTcxYi00MDRjLWFhYjgtOTViNzI5ZTgxZjRjIiwiaXNzIjoiYWU2MmRmNzItMzQ5MS00M2EwLWFhOTAtMTkzZTRhMTQwM2Q4IiwiaWF0IjoiMjAyMS0wOS0wNlQwODowNjo0NS43NjE2M1oiLCJleHAiOiIyMDI2LTA5LTA1VDA4OjA2OjQ1Ljc2MTYzWiIsInB1YiI6IjFoUEtZSmR6NnQxNU53Nzkzd0hOZFRpWWhFdWszVmlUeWVqdEV6VktxUTF0Z1drYVJMbzl4IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSIsImlzc3VlIl19.Aan/ubpcX3/jL+wuBjSZ/HOeRH9KTZMgEMMffTjReC0G10ExriUfk6cEFO9Hl3HeCSZCSnYdycA+SOj6ZQ+hnwQ";
    private static Key _intermediateKey;
    private static Identity _intermediateIdentity;

    // -- ISSUER IDENTITY (SENDER) --
    private static final String _encodedIssuerKey = "Di:KEY.eyJ1aWQiOiIyMjMxNjE5MS0yNTZkLTQ5MjYtOTQ3MS0zYTljYjAwZGJlZjYiLCJpYXQiOiIyMDIxLTA5LTA2VDA4OjA3OjI2LjY1MjM2WiIsImtleSI6IjFoRWpnenFVTTZocXBNZW1wQlFqY1pDd0h2c0s4eTU3Y1hVSEF6dmNtbjRiekxRYllXUVpMIiwicHViIjoiMWhQS2R0Q0FxNGJ2ZllZYkVXNWJxTWpGY0tHc3c3R3Jxb252cXJrVjRZRmM2Um1vMmR0a0EifQ";
    private static String _encodedIssuerIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiNjQwNDRiNzctYzQxMC00MmY2LWFhZjktZmZhZWVhMDVkZjA0Iiwic3ViIjoiZDRlZTdmMjktNjkzYi00MmNjLTgzZjMtZGRjMjQ3OWQ1NDc1IiwiaXNzIjoiOTEyZWQ5YmEtYTcxYi00MDRjLWFhYjgtOTViNzI5ZTgxZjRjIiwiaWF0IjoiMjAyMS0wOS0wNlQwODowNzoyNi42ODg3MDlaIiwiZXhwIjoiMjAyMi0wOS0wNlQwODowNzoyNi42ODg3MDlaIiwicHViIjoiMWhQS2R0Q0FxNGJ2ZllZYkVXNWJxTWpGY0tHc3c3R3Jxb252cXJrVjRZRmM2Um1vMmR0a0EiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UWXhZelEzWkdJdE1UYzJPQzAwTkdJMExUaGhPVEF0WkdSaE9XRmlaVGRpWW1Oaklpd2ljM1ZpSWpvaU9URXlaV1E1WW1FdFlUY3hZaTAwTURSakxXRmhZamd0T1RWaU56STVaVGd4WmpSaklpd2lhWE56SWpvaVlXVTJNbVJtTnpJdE16UTVNUzAwTTJFd0xXRmhPVEF0TVRrelpUUmhNVFF3TTJRNElpd2lhV0YwSWpvaU1qQXlNUzB3T1Mwd05sUXdPRG93TmpvME5TNDNOakUyTTFvaUxDSmxlSEFpT2lJeU1ESTJMVEE1TFRBMVZEQTRPakEyT2pRMUxqYzJNVFl6V2lJc0luQjFZaUk2SWpGb1VFdFpTbVI2Tm5ReE5VNTNOemt6ZDBoT1pGUnBXV2hGZFdzelZtbFVlV1ZxZEVWNlZrdHhVVEYwWjFkcllWSk1iemw0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BYW4vdWJwY1gzL2pMK3d1QmpTWi9IT2VSSDlLVFpNZ0VNTWZmVGpSZUMwRzEwRXhyaVVmazZjRUZPOUhsM0hlQ1NaQ1NuWWR5Y0ErU09qNlpRK2hud1E.Aducef6L7vnEEG4+DI9ZR5REWZ53gfgTyXuCr+UJw/Pad3Hqm45wqkk2iGL/NzBHOtJ16grwc5m0yiWZLoJAtwM";
    private static Key _issuerKey;
    private static Identity _issuerIdentity;

    // -- AUDIENCE IDENTITY (RECEIVER) --
    private static final String _encodedAudienceKey = "Di:KEY.eyJ1aWQiOiI2OWE5OTA3Mi1lN2Y3LTRjYWMtYjA3Yy01ZTcyZTgxYTI4YmQiLCJpYXQiOiIyMDIxLTA5LTA2VDA4OjA4OjE2LjYwNzE5OFoiLCJrZXkiOiIxaEVqUGJUQXFWZzJZWVd3Q0JETlFRM2ZDckF6eDZ2QXlEVlFZdU52Skp4VTNxZ1dpSkJrUyIsInB1YiI6IjFoUEtIU1RkM0RDZDNwNDFTaXlRc1lnV0tLaDhReUpIdXh4Z1RSYUFBWUZZN2VvdXVNRkprIn0";
    private static final String _encodedAudienceIdentity = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiMmEwZjQxMTQtZWY0OC00ZjAwLWJlOWItZWNhNDkzZTQ0MDZlIiwic3ViIjoiMjI2M2EwMTctZWU1YS00ZDJhLWEzZmUtZTY5ZjkyNjJhNjAxIiwiaXNzIjoiOTEyZWQ5YmEtYTcxYi00MDRjLWFhYjgtOTViNzI5ZTgxZjRjIiwiaWF0IjoiMjAyMS0wOS0wNlQwODowODoxNi42NDQwMVoiLCJleHAiOiIyMDIyLTA5LTA2VDA4OjA4OjE2LjY0NDAxWiIsInB1YiI6IjFoUEtIU1RkM0RDZDNwNDFTaXlRc1lnV0tLaDhReUpIdXh4Z1RSYUFBWUZZN2VvdXVNRkprIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UWXhZelEzWkdJdE1UYzJPQzAwTkdJMExUaGhPVEF0WkdSaE9XRmlaVGRpWW1Oaklpd2ljM1ZpSWpvaU9URXlaV1E1WW1FdFlUY3hZaTAwTURSakxXRmhZamd0T1RWaU56STVaVGd4WmpSaklpd2lhWE56SWpvaVlXVTJNbVJtTnpJdE16UTVNUzAwTTJFd0xXRmhPVEF0TVRrelpUUmhNVFF3TTJRNElpd2lhV0YwSWpvaU1qQXlNUzB3T1Mwd05sUXdPRG93TmpvME5TNDNOakUyTTFvaUxDSmxlSEFpT2lJeU1ESTJMVEE1TFRBMVZEQTRPakEyT2pRMUxqYzJNVFl6V2lJc0luQjFZaUk2SWpGb1VFdFpTbVI2Tm5ReE5VNTNOemt6ZDBoT1pGUnBXV2hGZFdzelZtbFVlV1ZxZEVWNlZrdHhVVEYwWjFkcllWSk1iemw0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BYW4vdWJwY1gzL2pMK3d1QmpTWi9IT2VSSDlLVFpNZ0VNTWZmVGpSZUMwRzEwRXhyaVVmazZjRUZPOUhsM0hlQ1NaQ1NuWWR5Y0ErU09qNlpRK2hud1E.AXB8AHIh3K0zlMzGK7oU3ddkpx8o/Qp26z5ktSSFS6jDZrtVonDERc6GfDhCsG7xYVOkktirBc/tAsbKW3jk3wk";
    private static Key _audienceKey;
    private static Identity _audienceIdentity;

}
