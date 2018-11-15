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
        pFilter.addRule(new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW));

        EventFilter nFilter = new EventFilter();
        assertNotNull(nFilter);
        nFilter.addRule(new EventFilterRule()
            .wantSubtype(Payload.PayloadType.CLOUDTRAIL));

        Parser p = new Parser();
        assertNotNull(p);
        Event e = p.parse("test");
        assertNotNull(e);
        assertEquals(Payload.PayloadType.RAW, e.getPayloadType());

        assertTrue(pFilter.matches(e));
        assertFalse(nFilter.matches(e));
    }

    @Test
    public void testEventFilterRawPayload() throws Exception {
        EventFilter pFilter = new EventFilter();
        assertNotNull(pFilter);
        pFilter.addRule(new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(new EventFilterPayload(Raw.class)
                .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

        EventFilter icFilter = new EventFilter();
        assertNotNull(icFilter);
        icFilter.addRule(new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(new EventFilterPayload(GLB.class) // Wrong payload type
                .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

        EventFilter nFilter = new EventFilter();
        assertNotNull(nFilter);
        nFilter.addRule(new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(new EventFilterPayload(Raw.class)
                .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "nomatch")));

        Parser p = new Parser();
        assertNotNull(p);
        Event e = p.parse("test");
        assertNotNull(e);
        assertEquals(Payload.PayloadType.RAW, e.getPayloadType());

        assertTrue(pFilter.matches(e));
        assertFalse(nFilter.matches(e));
        assertFalse(icFilter.matches(e));
    }
}
