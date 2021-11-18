//
//  Base58Test.java
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class Base58Test {

    @Test
    void encodeTest1() {
        String ref = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";
        byte[] bytes = new byte[]{ (byte)0x21, (byte)0x1b, (byte)0x74, (byte)0xca, (byte)0x46, (byte)0x86, (byte)0xf8, (byte)0x1e, (byte)0xfd, (byte)0xa5, (byte)0x64, (byte)0x17, (byte)0x67, (byte)0xfc, (byte)0x84, (byte)0xef, (byte)0x16, (byte)0xda, (byte)0xfe, (byte)0x0b };
        String b58 = Base58.encode(bytes, new byte[]{ (byte)0x00 });
        assertEquals(ref, b58);
    }

    @Test
    void decodeTest1() {
        String base58 = "1RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDCQndpL"; //"4jummFx8watBhHhr7pW1u32g8JGPipX5qCJvMMxR";
        byte[] bytes = Base58.decode(base58);
        assertTrue(bytes[0] == (byte)0x00);
        String decoded = new String(Utility.subArray(bytes, 1), StandardCharsets.UTF_8);
       assertEquals("Racecar is racecar backwards.", decoded);
    }
}