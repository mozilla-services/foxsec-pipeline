package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.ArrayList;
import java.util.Collection;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.transforms.ParDo;
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
    PAssert.thatSingleton(pcount).isEqualTo(1L);

    PCollection<Long> ncount = nfiltered.apply("ncount", Count.globally());
    PAssert.thatSingleton(ncount).isEqualTo(0L);

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
    PAssert.thatSingleton(pcount).isEqualTo(1L);

    PCollection<Long> ncount = nfiltered.apply("ncount", Count.globally());
    PAssert.thatSingleton(ncount).isEqualTo(0L);

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
    PAssert.thatSingleton(count).isEqualTo(2L);

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule().wantSubtype(Payload.PayloadType.GLB).wantStackdriverProject("moz"));
    filtered = input.apply("match one", EventFilter.getTransform(filter));
    count = filtered.apply("count one", Count.globally());
    PAssert.thatSingleton(count).isEqualTo(1L);
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
