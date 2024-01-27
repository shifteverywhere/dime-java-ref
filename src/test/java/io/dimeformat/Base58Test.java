//
//  Base58Test.java
//  Di:ME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//
package io.dimeformat;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class Base58Test {

    @Test
    void encodeTest1() {
        String ref = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";
        byte[] bytes = new byte[]{ (byte)0x00, (byte)0x21, (byte)0x1b, (byte)0x74, (byte)0xca, (byte)0x46, (byte)0x86, (byte)0xf8, (byte)0x1e, (byte)0xfd, (byte)0xa5, (byte)0x64, (byte)0x17, (byte)0x67, (byte)0xfc, (byte)0x84, (byte)0xef, (byte)0x16, (byte)0xda, (byte)0xfe, (byte)0x0b };
        String b58 = Base58.encode(bytes);
        assertEquals(ref, b58);
    }

    @Test
    void encodeTest2() {
        String ref = Commons.PAYLOAD;
        String b58 = Base58.encode(ref.getBytes(StandardCharsets.UTF_8));
        assertEquals("RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDACaR79", b58);
    }

    @Test
    void decodeTest1() {
        String base58 = "RUP8qykPEgwU7tFVRBorfw2BdwmQX9q9VR5oELDACaR79";
        byte[] bytes = Base58.decode(base58);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        assertEquals(Commons.PAYLOAD, decoded);
    }

    @Test
    void decodeTest2() {
        String base64 = Utility.toBase64(Commons.PAYLOAD.getBytes(StandardCharsets.UTF_8));
        byte[] bytes = Base58.decode(base64);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        assertTrue(decoded.isEmpty());
    }

    @Test
    void decodeTest3() {
        String base64 = Utility.toHex(Utility.randomBytes(256));
        byte[] bytes = Base58.decode(base64);
        String decoded = new String(bytes, StandardCharsets.UTF_8);
        assertTrue(decoded.isEmpty());
    }

}
