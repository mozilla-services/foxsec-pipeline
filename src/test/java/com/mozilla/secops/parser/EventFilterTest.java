package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Test;

public class EventFilterTest {
  public EventFilterTest() {}

  private static ObjectMapper mapper = new ObjectMapper();

  private EventFilter reload(EventFilter filter) throws Exception {
    return mapper.readValue(mapper.writeValueAsString(filter), EventFilter.class);
  }

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

    assertTrue(reload(pFilter).matches(e));
    assertFalse(reload(nFilter).matches(e));
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

    assertTrue(reload(pFilter).matches(e));
    assertTrue(reload(prFilter).matches(e));
    assertFalse(reload(nFilter).matches(e));
    assertFalse(reload(icFilter).matches(e));
    assertFalse(reload(nrFilter).matches(e));
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
    assertTrue(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER, "riker")));
    assertTrue(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER, "test")));
    assertFalse(reload(filter).matches(e));
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
    assertTrue(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverProject("nonexistent"));
    assertFalse(reload(filter).matches(e));
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
    assertTrue(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverLabel("application", "nonexistent"));
    assertFalse(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(new EventFilterRule().wantStackdriverLabel("nonexistent", "bugzilla"));
    assertFalse(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantStackdriverLabel("application", "bugzilla")
            .wantStackdriverLabel("env", "testing"));
    assertFalse(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantStackdriverLabel("application", "bugzilla")
            .wantStackdriverLabel("env", "test"));
    assertTrue(reload(filter).matches(e));
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
    assertTrue(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertFalse(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 201)));
    assertFalse(reload(filter).matches(e));

    filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayload(GLB.class)
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                    .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")));
    assertFalse(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertTrue(reload(filter).matches(e));

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
    assertFalse(reload(filter).matches(e));

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
    assertFalse(reload(filter).matches(e));
  }

  @Test
  public void testEventFilterOrMatch() throws Exception {
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

    // Single entry OR filter
    EventFilter filter = new EventFilter();
    assertNotNull(filter);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.GLB)
            .addPayloadFilter(
                new EventFilterPayloadOr()
                    .addPayloadFilter(
                        new EventFilterPayload(GLB.class)
                            .withStringMatch(
                                EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
                            .withIntegerMatch(
                                EventFilterPayload.IntegerProperty.GLB_STATUS, 200))));

    // Multiple entry OR filter, one matching
    filter = new EventFilter();
    assertNotNull(filter);
    EventFilterRule rule = new EventFilterRule().wantSubtype(Payload.PayloadType.GLB);
    EventFilterPayloadOr filterOr = new EventFilterPayloadOr();
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST")
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200));
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET")
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200));
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "HEAD")
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200));
    rule.addPayloadFilter(filterOr);
    filter.addRule(rule);
    assertTrue(reload(filter).matches(e));

    // Multiple entry OR filter with additional payload filter
    filter = new EventFilter();
    assertNotNull(filter);
    rule = new EventFilterRule().wantSubtype(Payload.PayloadType.GLB);
    filterOr = new EventFilterPayloadOr();
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST"));
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET"));
    rule.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 200));
    rule.addPayloadFilter(filterOr);
    filter.addRule(rule);
    assertTrue(reload(filter).matches(e));

    // Multiple entry OR filter with additional payload filter, additional not matching
    filter = new EventFilter();
    assertNotNull(filter);
    rule = new EventFilterRule().wantSubtype(Payload.PayloadType.GLB);
    filterOr = new EventFilterPayloadOr();
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "POST"));
    filterOr.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withStringMatch(EventFilterPayload.StringProperty.GLB_REQUESTMETHOD, "GET"));
    rule.addPayloadFilter(
        new EventFilterPayload(GLB.class)
            .withIntegerMatch(EventFilterPayload.IntegerProperty.GLB_STATUS, 403));
    rule.addPayloadFilter(filterOr);
    filter.addRule(rule);
    assertFalse(reload(filter).matches(e));
  }

  @Test
  public void testEventFilterSerialize() throws Exception {
    EventFilter filter = new EventFilter().setWantUTC(true);
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .wantStackdriverLabel("labelname", "labelvalue")
            .wantStackdriverProject("testing")
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    String buf = mapper.writeValueAsString(filter);
    filter = mapper.readValue(buf, EventFilter.class);
    assertEquals(buf, mapper.writeValueAsString(filter));

    filter = new EventFilter().setWantUTC(true);
    filter.addRule(
        new EventFilterRule()
            .wantNormalizedType(Normalized.Type.AUTH)
            .wantStackdriverLabel("labelname", "labelvalue")
            .wantStackdriverProject("testing")
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER, "test"))
            .addPayloadFilter(
                new EventFilterPayloadOr()
                    .addPayloadFilter(new EventFilterPayload(OpenSSH.class))
                    .addPayloadFilter(new EventFilterPayload(BmoAudit.class))));

    buf = mapper.writeValueAsString(filter);
    filter = mapper.readValue(buf, EventFilter.class);
    assertEquals(buf, mapper.writeValueAsString(filter));

    filter = new EventFilter().passConfigurationTicks().setWantUTC(true);
    EventFilterRule rule = new EventFilterRule().wantNormalizedType(Normalized.Type.HTTP_REQUEST);
    rule.except(
        new EventFilterRule()
            .wantNormalizedType(Normalized.Type.HTTP_REQUEST)
            .addPayloadFilter(
                new EventFilterPayload()
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_REQUESTMETHOD, "POST")
                    .withStringMatch(
                        EventFilterPayload.StringProperty.NORMALIZED_URLREQUESTPATH, "/testing"))
            .addPayloadFilter(
                new EventFilterPayloadOr()
                    .addPayloadFilter(
                        new EventFilterPayload()
                            .withIntegerRangeMatch(
                                EventFilterPayload.IntegerProperty.NORMALIZED_REQUESTSTATUS,
                                0,
                                399))
                    .addPayloadFilter(
                        new EventFilterPayload()
                            .withIntegerRangeMatch(
                                EventFilterPayload.IntegerProperty.NORMALIZED_REQUESTSTATUS,
                                500,
                                Integer.MAX_VALUE))));
    filter.addRule(rule);

    buf = mapper.writeValueAsString(filter);
    filter = mapper.readValue(buf, EventFilter.class);
    assertEquals(buf, mapper.writeValueAsString(filter));
  }
}
