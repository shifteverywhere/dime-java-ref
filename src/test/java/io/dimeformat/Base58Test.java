package io.dimeformat;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Base58Test {

    @Test
    void encodeTest1() {

        byte[] bytes = "Racecar is racecar backwards.".getBytes(StandardCharsets.UTF_8);
        //byte[] bytes = { (byte)150, 71, 105, (byte)188, (byte)150, 71, 105, (byte)188, (byte)150, 71, 105, (byte)188, (byte)150, 71, 105, (byte)188, (byte)150, 71, 105, (byte)188 };
        String b58 = Base58.encode(bytes);
        System.out.println(b58);


    }

    @Test
    void decodeTest1() {
    }
}