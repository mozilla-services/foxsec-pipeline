package com.mozilla.secops.parser;

import org.junit.Test;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class EventFilterTest {
    public EventFilterTest() {
    }

    @Test
    public void testEventFilterRaw() throws Exception {
        EventFilter pFilter = new EventFilter();
        assertNotNull(pFilter);
        pFilter.wantSubtype(Payload.PayloadType.RAW);

        EventFilter nFilter = new EventFilter();
        assertNotNull(nFilter);
        nFilter.wantSubtype(Payload.PayloadType.CLOUDTRAIL);

        Parser p = new Parser();
        assertNotNull(p);
        Event e = p.parse("test");
        assertNotNull(e);
        assertEquals(Payload.PayloadType.RAW, e.getPayloadType());

        assertTrue(pFilter.matches(e));
        assertFalse(nFilter.matches(e));
    }
}
