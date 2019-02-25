package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Collection;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.ParDo;
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
              Event ev = results.get("bG9naW5GYWlsdXJl");
              assertNotNull(ev);
              ev = results.get("c2VjZXZlbnQubW9kZWwuMQ==");
              assertNull(ev);
              return null;
            });

    PAssert.thatMap(multiKeyed)
        .satisfies(
            results -> {
              Event ev = results.get("bG9naW5GYWlsdXJl cUB0aGUtcS1jb250aW51dW0=");
              assertNotNull(ev);
              ev = results.get("bG9naW5GYWlsdXJl");
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
              Event ev = results.get("cmlrZXI= cHVibGlja2V5");
              assertNotNull(ev);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testTransformStackdriverProjectFilter() throws Exception {
    ArrayList<String> buf = new ArrayList<>();
    buf.add(
        "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":"
            + "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt"
            + "ps://send.firefox.com/public/locales/en-US/send.js?test=test\",\"responseSize\":\"2692\","
            + "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M"
            + "ac OS X 10_13_3)"
            + "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@type\":\"type.googleapis.com/"
            + "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent"
            + "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim"
            + "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_"
            + "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-"
            + "6cb3697\",\"project_id\":\"test\",\"target_proxy_name\":\"k8s-tps-prod-"
            + "97\",\"url_map_name\":\"k8s-um-prod"
            + "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}"
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:"
            + "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA\"}");
    buf.add(
        "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":"
            + "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt"
            + "ps://send.firefox.com/public/locales/en-US/send.js?test=test\",\"responseSize\":\"2692\","
            + "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M"
            + "ac OS X 10_13_3)"
            + "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@type\":\"type.googleapis.com/"
            + "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent"
            + "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim"
            + "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_"
            + "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-"
            + "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-"
            + "97\",\"url_map_name\":\"k8s-um-prod"
            + "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}"
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:"
            + "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA\"}");

    PCollection<Event> input = pipeline.apply(Create.of(buf)).apply(ParDo.of(new ParserDoFn()));

    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GLB));
    PCollection<Event> filtered = input.apply("match all", EventFilter.getTransform(filter));
    PCollection<Long> count = filtered.apply("count all", Count.globally());
    PAssert.that(count).containsInAnyOrder(2L);

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule().wantSubtype(Payload.PayloadType.GLB).wantStackdriverProject("moz"));
    filtered = input.apply("match one", EventFilter.getTransform(filter));
    count = filtered.apply("count one", Count.globally());
    PAssert.that(count).containsInAnyOrder(1L);
    PAssert.that(filtered)
        .satisfies(
            x -> {
              Event[] e = ((Collection<Event>) x).toArray(new Event[0]);
              assertEquals(1, e.length);
              assertEquals("moz", e[0].getStackdriverProject());
              return null;
            });

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .wantStackdriverProject("nonexistent"));
    filtered = input.apply("match none", EventFilter.getTransform(filter));
    PAssert.that(filtered).empty();

    pipeline.run().waitUntilFinish();
  }
}
