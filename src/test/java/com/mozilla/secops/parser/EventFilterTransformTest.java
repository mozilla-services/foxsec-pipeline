package com.mozilla.secops.parser;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class EventFilterTransformTest {
  public EventFilterTransformTest() {}

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void testTransformPayloadMatch() throws Exception {
    Parser p = new Parser();
    Event e = p.parse("picard");
    assertNotNull(e);
    PCollection<Event> input = pipeline.apply(Create.of(e));

    EventFilter pFilter = new EventFilter();
    assertNotNull(pFilter);
    pFilter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.RAW));

    EventFilter nFilter = new EventFilter();
    assertNotNull(nFilter);
    nFilter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GLB));

    PCollection<Event> pfiltered = input.apply("positive", EventFilter.getTransform(pFilter));
    PCollection<Event> nfiltered = input.apply("negative", EventFilter.getTransform(nFilter));

    PCollection<Long> pcount = pfiltered.apply("pcount", Count.globally());
    PAssert.that(pcount).containsInAnyOrder(1L);

    PCollection<Long> ncount = nfiltered.apply("ncount", Count.globally());
    PAssert.that(ncount).containsInAnyOrder(0L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testTransformPayloadMatchRaw() throws Exception {
    Parser p = new Parser();
    Event e = p.parse("picard");
    assertNotNull(e);
    PCollection<Event> input = pipeline.apply(Create.of(e));

    EventFilter pFilter = new EventFilter();
    assertNotNull(pFilter);
    pFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "picard")));

    EventFilter nFilter = new EventFilter();
    assertNotNull(nFilter);
    nFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "jean-luc")));

    PCollection<Event> pfiltered = input.apply("positive", EventFilter.getTransform(pFilter));
    PCollection<Event> nfiltered = input.apply("negative", EventFilter.getTransform(nFilter));

    PCollection<Long> pcount = pfiltered.apply("pcount", Count.globally());
    PAssert.that(pcount).containsInAnyOrder(1L);

    PCollection<Long> ncount = nfiltered.apply("ncount", Count.globally());
    PAssert.that(ncount).containsInAnyOrder(0L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testTransformKeying() throws Exception {
    String buf =
        "{\"secevent_version\":\"secevent.model.1\",\"action\":\"loginFailure\""
            + ",\"account_id\":\"q@the-q-continuum\",\"timestamp\":\"1970-01-01T00:00:00+00:00\"}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    PCollection<Event> input = pipeline.apply(Create.of(e));

    EventFilter filter = new EventFilter().matchAny();
    assertNotNull(filter);
    filter.addKeyingSelector(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.SECEVENT)
            .addPayloadFilter(
                new EventFilterPayload(SecEvent.class)
                    .withStringSelector(EventFilterPayload.StringProperty.SECEVENT_ACTION)));

    EventFilter multiFilter = new EventFilter().matchAny();
    assertNotNull(multiFilter);
    multiFilter.addKeyingSelector(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.SECEVENT)
            .addPayloadFilter(
                new EventFilterPayload(SecEvent.class)
                    .withStringSelector(EventFilterPayload.StringProperty.SECEVENT_ACTION)
                    .withStringSelector(EventFilterPayload.StringProperty.SECEVENT_ACCOUNTID)));

    PCollection<KV<String, Event>> keyed =
        input.apply("filter", EventFilter.getKeyingTransform(filter));
    PCollection<KV<String, Event>> multiKeyed =
        input.apply("multiFilter", EventFilter.getKeyingTransform(multiFilter));

    PAssert.thatMap(keyed)
        .satisfies(
            results -> {
              Event ev = results.get("loginFailure");
              assertNotNull(ev);
              ev = results.get("secevent.model.1");
              assertNull(ev);
              return null;
            });

    PAssert.thatMap(multiKeyed)
        .satisfies(
            results -> {
              Event ev = results.get("loginFailure+q@the-q-continuum");
              assertNotNull(ev);
              ev = results.get("loginFailure");
              assertNull(ev);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testTransformKeyingNormalized() throws Exception {
    String buf =
        "Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    PCollection<Event> input = pipeline.apply(Create.of(e));

    EventFilter filter = new EventFilter().matchAny();
    assertNotNull(filter);
    filter.addKeyingSelector(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringSelector(EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER)));
    filter.addKeyingSelector(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload(OpenSSH.class)
                    .withStringSelector(EventFilterPayload.StringProperty.OPENSSH_AUTHMETHOD)));

    PCollection<KV<String, Event>> keyed =
        input.apply("filter", EventFilter.getKeyingTransform(filter));

    PAssert.thatMap(keyed)
        .satisfies(
            results -> {
              Event ev = results.get("riker+publickey");
              assertNotNull(ev);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }
}
