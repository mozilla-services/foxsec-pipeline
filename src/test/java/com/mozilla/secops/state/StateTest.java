package com.mozilla.secops.state;

import org.junit.rules.ExpectedException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Test;

import java.io.IOException;

public class StateTest {
    static class TestClass {
        public String s;
    }

    public StateTest() {
    }

    @Test
    public void testStateConstruct() throws Exception {
        State s = new State(new SimpleStateInterface());
        assertNotNull(s);
    }

    @Test
    public void testSimpleStateSetGet() throws Exception {
        State s = new State(new SimpleStateInterface());
        TestClass t = new TestClass();
        assertNotNull(t);
        t.s = "test";
        s.set("testing", t);
        t = s.get("testing", TestClass.class);
        assertNotNull(t);
        assertEquals("test", t.s);
    }

    @Test
    public void testSimpleStateSetGetNoExist() throws Exception {
        State s = new State(new SimpleStateInterface());
        TestClass t = new TestClass();
        assertNotNull(t);
        t.s = "test";
        s.set("testing", t);
        t = s.get("testing", TestClass.class);
        assertNotNull(t);
        assertEquals("test", t.s);

        assertNull(s.get("nonexist", TestClass.class));
    }
}
