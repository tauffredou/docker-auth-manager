package org.tauf.docker.domain;


import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;

public class TokenTest {


    @Test
    public void test_decode_encode() throws IOException {
        Token token = Token.decode("eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6ImFkbWluIn0");

        Assert.assertEquals("alice",token.getUsername());
        Assert.assertEquals("admin",token.getRole());

        Assert.assertEquals("eyJ1c2VybmFtZSI6ImFsaWNlIiwicm9sZSI6ImFkbWluIn0", token.encode());
    }

}