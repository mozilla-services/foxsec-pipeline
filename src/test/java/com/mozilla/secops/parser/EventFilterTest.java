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

    EventFilter prFilter = new EventFilter();
    assertNotNull(prFilter);
    prFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringRegexMatch(EventFilterPayload.StringProperty.RAW_RAW, "\\west")));

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

    EventFilter nrFilter = new EventFilter();
    assertNotNull(nrFilter);
    nFilter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringRegexMatch(EventFilterPayload.StringProperty.RAW_RAW, "\\wesr")));

    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse("test");
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());

    assertTrue(pFilter.matches(e));
    assertTrue(prFilter.matches(e));
    assertFalse(nFilter.matches(e));
    assertFalse(icFilter.matches(e));
    assertFalse(nrFilter.matches(e));
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

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER, "riker")));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER, "test")));
    assertFalse(filter.matches(e));
  }

  @Test
  public void testEventFilterStackdriverProjectFilter() throws Exception {
    String buf =
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
            + "AAAAAAAAAA\"}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GLB, e.getPayloadType());
    assertEquals("test", e.getStackdriverProject());

    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverProject("test"));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverProject("nonexistent"));
    assertFalse(filter.matches(e));
  }

  @Test
  public void testEventFilterStackdriverLabelFilter() throws Exception {
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAA\",\"jsonPayload\":{\"agent\":\"Mozilla/5.0\",\"bytes_sent\""
            + ":\"97\",\"cache_status\":\"-\",\"code\":\"200\",\"gzip_ratio\":\"0.68\",\"referrer\":\"h"
            + "ttps://bugzilla.mozilla.org/show_bug.cgi?id=0\",\"remote_ip\":\"216.160.83.56\",\"req_ti"
            + "me\":\"0.136\",\"request\":\"POST /rest/bug_user_last_visit/000000?t=t HTTP/1.1\",\"res_"
            + "time\":\"0.136\"},\"labels\":{\"application\":\"bugzilla\",\"ec2.amazonaws.com/resource_"
            + "name\":\"ip1.us-west-2.compute.internal\",\"env\":\"test\",\"stack\":\"app\",\"type\":\""
            + "app\"},\"logName\":\"projects/test/logs/test\",\"receiveTimestamp\":\"2019-01-31T17:49:5"
            + "9.539710898Z\",\"resource\":{\"labels\":{\"aws_account\":\"000000000000\",\"instance_id\""
            + ":\"i-00000000000000000\",\"project_id\":\"test\",\"region\":\"aws:us-west-2c\"},\"type\":"
            + "\"aws_ec2_instance\"},\"timestamp\":\"2019-01-31T17:49:57Z\"}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.NGINX, e.getPayloadType());

    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverLabel("application", "bugzilla"));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverLabel("application", "nonexistent"));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverLabel("nonexistent", "bugzilla"));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantStackdriverLabel("application", "bugzilla")
            .wantStackdriverLabel("env", "testing"));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantStackdriverLabel("application", "bugzilla")
            .wantStackdriverLabel("env", "test"));
    assertTrue(filter.matches(e));
  }

  @Test
  public void testEventFilterMultitypeMatch() throws Exception {
    String buf =
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
            + "AAAAAAAAAA\"}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GLB, e.getPayloadType());

    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200)));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 201)
                    .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200)));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    EventFilterRule rule =
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET"));
    rule.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200));
    filter.addRule(rule);
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    rule =
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET"));
    rule.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 201));
    filter.addRule(rule);
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 201)));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")));
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .except(
                new EventFilterRule()
                    .wantSubtype(Payload.PayloadType.GLB)
                    .addPayloadFilter(
                        new EventFilterPayload(GLB.class)
                            .withStringMatch(
                                EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST"))));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .except(
                new EventFilterRule()
                    .wantSubtype(Payload.PayloadType.GLB)
                    .addPayloadFilter(
                        new EventFilterPayload(GLB.class)
                            .withStringMatch(
                                EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")))
            .except(new EventFilterRule().wantStackdriverProject("project")));
    assertTrue(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .except(
                new EventFilterRule()
                    .wantSubtype(Payload.PayloadType.GLB)
                    .addPayloadFilter(
                        new EventFilterPayload(GLB.class)
                            .withStringMatch(
                                EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")))
            .except(new EventFilterRule().wantStackdriverProject("project"))
            .except(new EventFilterRule().wantStackdriverProject("test")));
    assertFalse(filter.matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .except(
                new EventFilterRule()
                    .wantSubtype(Payload.PayloadType.GLB)
                    .addPayloadFilter(
                        new EventFilterPayload(GLB.class)
                            .withStringMatch(
                                EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET"))));
    assertFalse(filter.matches(e));
  }
}
