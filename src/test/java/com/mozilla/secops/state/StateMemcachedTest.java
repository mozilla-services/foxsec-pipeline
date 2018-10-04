package com.mozilla.secops.state;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import org.junit.Test;

public class StateMemcachedTest {
    public StateMemcachedTest() {
    }

    @Test(expected = StateException.class)
    public void testMemcachedNoConnectionGet() throws Exception {
        State s = new State(new MemcachedStateInterface("127.0.0.1", 11212));
        assertNotNull(s);
        s.initialize();
        s.get("testing", StateTestClass.class);
    }
}
