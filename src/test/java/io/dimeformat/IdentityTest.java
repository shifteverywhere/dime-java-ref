package io.dimeformat;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class IdentityTest {

    @Test
    void getTagTest1() {
        Identity identity = new Identity(Commons.SYSTEM_NAME, null, null, null, null, null, null);
        assertEquals("ID", identity.getTag());
    }
}