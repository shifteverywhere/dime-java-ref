package io.dimeformat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MessageTest {

    @Test
    void getTagTest1() {
        Message message = new Message(null, -1);
        assertEquals("MSG", message.getTag());
    }
}