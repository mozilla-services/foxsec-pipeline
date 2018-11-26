package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EventFilterTest {
  public EventFilterTest() {}

  @Test
  public void testEventFilterRaw() throws Exception {
    EventFilter pFilter = new EventFilter();
    assertNotNull(pFilter);
    pFilter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.RAW));

    EventFilter nFilter = new EventFilter();
    assertNotNull(nFilter);
    nFilter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CLOUDTRAIL));

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
    pFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    EventFilter icFilter = new EventFilter();
    assertNotNull(icFilter);
    icFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class) // Wrong payload type
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    EventFilter nFilter = new EventFilter();
    assertNotNull(nFilter);
    nFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
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

  @Test
  public void testEventFilterNormalized() throws Exception {
    String buf =
        "Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));

    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH));
    assertTrue(filter.matches(e));
  }
}
