package com.mozilla.secops.parser;

import static org.junit.Assert.*;

import com.amazonaws.services.guardduty.model.Finding;
import com.maxmind.geoip2.model.CityResponse;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import java.util.ArrayList;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.junit.Test;

public class ParserTest {
  public static final String TEST_GEOIP_DBPATH = "/testdata/GeoIP2-City-Test.mmdb";

  public ParserTest() {}

  private Parser getTestParser() {
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(TEST_GEOIP_DBPATH);
    return new Parser(cfg);
  }

  @Test
  public void testParseZeroLength() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse("");
    assertNotNull(p);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("", r.getRaw());
  }

  @Test
  public void testParseNull() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(null);
    assertNotNull(p);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("", r.getRaw());
  }

  @Test
  public void testParseBadJson() throws Exception {
    String buf = "{\"testdata\": \"testing\", ";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(p);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals(buf, r.getRaw());
  }

  @Test
  public void testParseRaw() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse("test");
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("test", r.getRaw());
  }

  @Test
  public void testParserReuse() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse("test");
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("test", r.getRaw());

    e = p.parse("test2");
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    r = e.getPayload();
    assertNotNull(r);
    assertEquals("test2", r.getRaw());
  }

  @Test
  public void testStackdriverRaw() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource"
            + "_name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\""
            + ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"99999999999999"
            + "99999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\"te"
            + "xtPayload\":\"test\",\"timestamp\":\"2018-09-18T22:15:38Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("test", r.getRaw());
  }

  @Test
  public void testMozlogRaw() throws Exception {
    String buf =
        "{\"EnvVersion\": \"2.0\", \"Severity\": 6, \"Fields\": {\"numeric\": 3600, "
            + "\"string\": \"testing\"}, \"Hostname\": \"test\", \"Pid\": 62312, "
            + "\"Time\": \"2018-07-04T15:49:46Z\", \"Logger\": \"duopull\", \"Type\": \"app.log\", "
            + "\"Timestamp\": 1530719386349480000}";
    String expect = "{\"numeric\":3600,\"string\":\"testing\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals(expect, r.getRaw());
    Mozlog m = e.getMozlog();
    assertNotNull(m);
    assertEquals("test", m.getHostname());
    assertEquals("duopull", m.getLogger());
  }

  @Test
  public void testOpenSSHRaw() throws Exception {
    String buf =
        "Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    assertEquals(
        String.format("%d-09-18T22:15:38.000Z", new DateTime().getYear()),
        e.getTimestamp().toString());
    OpenSSH o = e.getPayload();
    assertNotNull(o);
    assertEquals("riker", o.getUser());
    assertEquals("publickey", o.getAuthMethod());
    assertEquals("127.0.0.1", o.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());
    assertEquals("emit-bastion", n.getObject());
  }

  @Test
  public void testOpenSSHStackdriver() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\""
            + ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999"
            + "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\""
            + "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp"
            + "\":\"2018-09-18T22:15:38Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertEquals("2018-09-18T22:15:38.000Z", e.getTimestamp().toString());
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    OpenSSH o = e.getPayload();
    assertNotNull(o);
    assertEquals("riker", o.getUser());
    assertEquals("publickey", o.getAuthMethod());
    assertEquals("127.0.0.1", o.getSourceAddress());
    assertNull(o.getSourceAddressCity());
    assertNull(o.getSourceAddressCountry());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());

    buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\""
            + ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999"
            + "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\""
            + "textPayload\":\"Feb  8 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
            + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp"
            + "\":\"2018-09-18T22:15:38Z\"}";
    p = new Parser();
    assertNotNull(p);
    e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    assertEquals("2018-02-08T22:15:38.000Z", e.getTimestamp().toString());
    o = e.getPayload();
    assertNotNull(o);
    assertEquals("riker", o.getUser());
    assertEquals("publickey", o.getAuthMethod());
    assertEquals("127.0.0.1", o.getSourceAddress());
    assertNull(o.getSourceAddressCity());
    assertNull(o.getSourceAddressCountry());
    n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());
  }

  @Test
  public void testOpenSSHStackdriverGeo() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\""
            + ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999"
            + "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\""
            + "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from "
            + "216.160.83.56 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp"
            + "\":\"2018-09-18T22:15:38Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    assertEquals("2018-09-18T22:15:38.000Z", e.getTimestamp().toString());
    OpenSSH o = e.getPayload();
    assertNotNull(o);
    assertEquals("riker", o.getUser());
    assertEquals("publickey", o.getAuthMethod());
    assertEquals("216.160.83.56", o.getSourceAddress());
    assertEquals("Milton", o.getSourceAddressCity());
    assertEquals("US", o.getSourceAddressCountry());
    assertEquals(47.25, o.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, o.getSourceAddressLongitude(), 0.5);
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
    assertEquals(47.25, n.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, n.getSourceAddressLongitude(), 0.5);
  }

  @Test
  public void testGLB() throws Exception {
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
            + "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-"
            + "97\",\"url_map_name\":\"k8s-um-prod"
            + "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}"
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:"
            + "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GLB, e.getPayloadType());
    GLB g = e.getPayload();
    assertNotNull(g);
    assertEquals("GET", g.getRequestMethod());
    assertEquals("127.0.0.1", g.getSourceAddress());
    assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3)", g.getUserAgent());
    assertEquals(
        "https://send.firefox.com/public/locales/en-US/send.js?test=test", g.getRequestUrl());
    assertEquals("2018-09-28T18:55:12.469Z", e.getTimestamp().toString());
    assertEquals(200, (int) g.getStatus());
    assertEquals("/public/locales/en-US/send.js", g.getParsedUrl().getPath());
    assertEquals("test=test", g.getParsedUrl().getQuery());
    assertEquals("send.firefox.com", g.getParsedUrl().getHost());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("GET", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals(
        "https://send.firefox.com/public/locales/en-US/send.js?test=test", n.getRequestUrl());
    assertEquals("/public/locales/en-US/send.js", n.getUrlRequestPath());
    assertEquals("send.firefox.com", n.getUrlRequestHost());
  }

  @Test
  public void testStackdriverJsonNoType() throws Exception {
    // Verify Stackdriver message with a JSON payload and no @type field is returned as a
    // raw event.
    String buf =
        "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":"
            + "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt"
            + "ps://send.firefox.com/public/locales/en-US/send.js\",\"responseSize\":\"2692\","
            + "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M"
            + "ac OS X 10_13_3)"
            + "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@usuallytype\":\"type.googleapis.com/"
            + "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent"
            + "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim"
            + "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_"
            + "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-"
            + "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-"
            + "97\",\"url_map_name\":\"k8s-um-prod"
            + "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}"
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:"
            + "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
  }

  @Test
  public void testGLBInvalidTimestamp() throws Exception {
    String buf =
        "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":"
            + "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt"
            + "ps://send.firefox.com/public/locales/en-US/send.js\",\"responseSize\":\"2692\","
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
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018"
            + "-1-1\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA"
            + "AAAAAAAAAA\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GLB, e.getPayloadType());
    GLB g = e.getPayload();
    assertNotNull(g);
    assertEquals("GET", g.getRequestMethod());
    assertEquals("127.0.0.1", g.getSourceAddress());
    assertEquals("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3)", g.getUserAgent());
    assertEquals("https://send.firefox.com/public/locales/en-US/send.js", g.getRequestUrl());
    assertNotNull(e.getTimestamp()); // Should have default timestamp
  }

  @Test
  public void testParseBmoAuditStackdriver() throws Exception {
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"EnvVersion\":2,\"Fields\":{\"msg\""
            + ":\"successful login of spock@mozilla.com from 216.160.83.56 using \\\"Mozilla/5.0\\\", auth"
            + "enticated by Bugzilla::Auth::Login::CGI\",\"remote_ip\":\"216.160.83.56\",\"request_id\""
            + ":\"00000000\"},\"Hostname\":\"ip-172.us-west-2.compute.internal\",\"Logger\":\"CEREAL\","
            + "\"Pid\":\"282\",\"Severity\":5,\"Timestamp\":1.548956727e+18,\"Type\":\"audit\"},\"label"
            + "s\":{\"application\":\"bugzilla\",\"ec2.amazonaws.com/resource_name\":\"ip-172.us-west-2"
            + ".compute.internal\",\"env\":\"prod\",\"stack\":\"app\",\"type\":\"app\"},\"logName\":\"p"
            + "rojects/prod/logs/docker.bugzilla\",\"receiveTimestamp\":\"2019-01-31T17:45:27.655836432"
            + "Z\",\"resource\":{\"labels\":{\"aws_account\":\"000000000000\",\"instance_id\":\"i-0\","
            + "\"project_id\":\"prod\",\"region\":\"aws:us-west-2a\"},\"type\":\"aws_ec2_instance\"},\""
            + "timestamp\":\"2019-01-31T17:45:27.478007784Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.BMOAUDIT, e.getPayloadType());
    assertEquals("2019-01-31T17:45:27.000Z", e.getTimestamp().toString());
    BmoAudit b = e.getPayload();
    assertEquals("216.160.83.56", b.getRemoteIp());
    assertEquals("00000000", b.getRequestId());
    assertEquals(BmoAudit.AuditType.LOGIN, b.getAuditType());
    assertEquals("spock@mozilla.com", b.getUser());
    assertEquals("Mozilla/5.0", b.getUserAgent());
    assertEquals("Milton", b.getSourceAddressCity());
    assertEquals("US", b.getSourceAddressCountry());
    assertEquals(47.25, b.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, b.getSourceAddressLongitude(), 0.5);
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("spock@mozilla.com", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
    assertEquals(47.25, n.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, n.getSourceAddressLongitude(), 0.5);
  }

  @Test
  public void testParseBmoAuditCreateBugStackdriver() throws Exception {
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAAA\",\"jsonPayload\":{\"EnvVersion\":2,\"Field"
            + "s\":{\"msg\":\"spock@mozilla.com <216.160.83.56> created bug 0000000\",\""
            + "remote_ip\":\"216.160.83.56\",\"request_id\":\"AAAAAAAA\",\"user_id\":\"0"
            + "00000\"},\"Hostname\":\"ip-172.us-west-2.compute.internal\",\"Logger\":\""
            + "CEREAL\",\"Pid\":\"264\",\"Severity\":5,\"Timestamp\":1.548956906e+18,\"T"
            + "ype\":\"audit\"},\"labels\":{\"application\":\"bugzilla\",\"ec2.amazonaws"
            + ".com/resource_name\":\"ip-172.us-west-2.compute.internal\",\"env\":\"prod"
            + "\",\"stack\":\"app\",\"type\":\"app\"},\"logName\":\"projects/prod/logs/d"
            + "ocker.bugzilla\",\"receiveTimestamp\":\"2019-01-31T17:48:29.488536026Z\",\""
            + "resource\":{\"labels\":{\"aws_account\":\"000000000000\",\"instance_id\":\""
            + "i-0\",\"project_id\":\"prod\",\"region\":\"aws:us-west-2a\"},\"type\":\"aws"
            + "_ec2_instance\"},\"timestamp\":\"2019-01-31T17:48:26.593764735Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.BMOAUDIT, e.getPayloadType());
    assertEquals("2019-01-31T17:48:26.000Z", e.getTimestamp().toString());
    BmoAudit b = e.getPayload();
    assertEquals("216.160.83.56", b.getRemoteIp());
    assertEquals("AAAAAAAA", b.getRequestId());
    assertEquals(BmoAudit.AuditType.CREATEBUG, b.getAuditType());
    assertEquals("spock@mozilla.com", b.getUser());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH_SESSION));
    assertEquals("spock@mozilla.com", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
  }

  @Test
  public void testParseIPrepdStackdriver() throws Exception {
    String buf =
        "{\"insertId\":\"sample-insert-id\",\"jsonPayload\":{\"Fields\":{\"exception\": false,"
            + "\"msg\":\"violation applied\",\"decay_after\":\"0001-01-01T00:00:00Z\",\"original_reputation\":"
            + "100,\"violation\": \"client_error_rate_violation\",\"reputation\": 80,\"type\":\"ip\","
            + "\"object\": \"10.0.0.1\"},\"Hostname\":\"sample-hostname\",\"Pid\": 9,\"EnvVersion\": \"1.0\","
            + "\"Type\": \"app.log\",\"Timestamp\": 1566313160510405740,\"Severity\": 9,\"Logger\":\"iprepd\","
            + "\"Time\": \"2019-08-20T15:05:10Z\"},\"timestamp\": \"2019-08-20T15:05:10.406089543Z\","
            + "\"severity\": \"INFO\",\"logName\": \"projects/sample-project/logs/stdout\","
            + "\"receiveTimestamp\": \"2019-08-20T15:05:12.671444870Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.IPREPD_LOG, e.getPayloadType());
    IPrepdLog log = e.getPayload();
    assertEquals("violation applied", log.getMsg());
    assertEquals(false, log.getException());
    assertEquals("10.0.0.1", log.getObject());
    assertEquals("ip", log.getObjectType());
    assertEquals("0001-01-01T00:00:00Z", log.getDecayAfter());
    assertEquals("100", log.getOriginalReputation().toString());
    assertEquals("80", log.getReputation().toString());
    assertEquals("client_error_rate_violation", log.getViolation());
  }

  @Test
  public void testParseIPrepdMozLog() throws Exception {
    String buf =
        "{\"Fields\":{\"exception\":false,\"msg\":\"violation applied\","
            + "\"decay_after\":\"0001-01-01T00:00:00Z\",\"original_reputation\": 100,"
            + "\"violation\": \"client_error_rate_violation\",\"reputation\": 80,\"type\":\"ip\","
            + "\"object\": \"10.0.0.1\"},\"Hostname\":\"sample-hostname\",\"Pid\": 9,\"EnvVersion\":\"1.0\","
            + "\"Type\":\"app.log\",\"Timestamp\": 1566313160510405740, \"Severity\": 9,\"Logger\":\"iprepd\","
            + "\"Time\": \"2019-08-20T15:05:10Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.IPREPD_LOG, e.getPayloadType());
    IPrepdLog log = e.getPayload();
    assertEquals("violation applied", log.getMsg());
    assertEquals(false, log.getException());
    assertEquals("10.0.0.1", log.getObject());
    assertEquals("ip", log.getObjectType());
    assertEquals("0001-01-01T00:00:00Z", log.getDecayAfter());
    assertEquals("100", log.getOriginalReputation().toString());
    assertEquals("80", log.getReputation().toString());
    assertEquals("client_error_rate_violation", log.getViolation());
  }

  @Test
  public void testParseMozlogDuopullBypass() throws Exception {
    String buf =
        "{\"EnvVersion\": \"2.0\", \"Severity\": 6, \"Fields\": "
            + "{\"event_description_valid_secs\": 3600, \"event_description_count\": 1, "
            + "\"event_description_user_id\": \"ZZZZZZZZZZZZZZZZZZZZ\", \"event_object\": \"worf\", "
            + "\"event_timestamp\": 1530282703, \"event_username\": \"First Last\", "
            + "\"event_description_bypass_code_ids\": [\"XXXXXXXXXXXXXXXXXXXX\"], "
            + "\"event_description_bypass\": \"\", \"path\": \"/admin/v1/logs/administrator\", "
            + "\"msg\": \"duopull event\", \"event_action\": \"bypass_create\", "
            + "\"event_description_auto_generated\": true, \"event_description_remaining_uses\": 1}, "
            + "\"Hostname\": \"test\", \"Pid\": 62312, \"Time\": \"2018-07-04T15:49:46Z\", "
            + "\"Logger\": \"duopull\", \"Type\": \"app.log\", \"Timestamp\": 1530719386349480000}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2018-06-29T14:31:43.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseDuopullBypass() throws Exception {
    String buf =
        "{\"event_description_valid_secs\": 3600, \"event_description_count\": 1, "
            + "\"event_description_user_id\": \"ZZZZZZZZZZZZZZZZZZZZ\", \"event_object\": \"worf\", "
            + "\"event_timestamp\": 1530282703, \"event_username\": \"First Last\", "
            + "\"event_description_bypass_code_ids\": [\"XXXXXXXXXXXXXXXXXXXX\"], "
            + "\"event_description_bypass\": \"\", \"path\": \"/admin/v1/logs/administrator\", "
            + "\"msg\": \"duopull event\", \"event_action\": \"bypass_create\", "
            + "\"event_description_auto_generated\": true, \"event_description_remaining_uses\": 1}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2018-06-29T14:31:43.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseStackdriverTextDuopullBypass() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp"
            + "\":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"999999999"
            + "9999999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance"
            + "\"},\"textPayload\":\"{\\\"EnvVersion\\\": \\\"2.0\\\", \\\"Severity\\\": 6, \\\"Fields\\\""
            + ": {\\\"event_description_valid_secs\\\": 3600, \\\"event_description_count\\\": 1, \\\"even"
            + "t_description_user_id\\\": \\\"ZZZZZZZZZZZZZZZZZZZZ\\\", \\\"event_object\\\": \\\"worf\\\""
            + ", \\\"event_timestamp\\\": 1530282703, \\\"event_username\\\": \\\"First Last\\\", \\\"even"
            + "t_description_bypass_code_ids\\\": [\\\"XXXXXXXXXXXXXXXXXXXX\\\"], \\\"event_description_by"
            + "pass\\\": \\\"\\\", \\\"path\\\": \\\"/admin/v1/logs/administrator\\\", \\\"msg\\\": \\\"du"
            + "opull event\\\", \\\"event_action\\\": \\\"bypass_create\\\", \\\"event_description_auto_ge"
            + "nerated\\\": true, \\\"event_description_remaining_uses\\\": 1}, \\\"Hostname\\\": \\\"test"
            + "\\\", \\\"Pid\\\": 62312, \\\"Time\\\": \\\"2018-07-04T15:49:46Z\\\", \\\"Logger\\\": \\\"d"
            + "uopull\\\", \\\"Type\\\": \\\"app.log\\\", \\\"Timestamp\\\": 1530719386349480000}\",\"time"
            + "stamp\":\"2018-09-18T22:15:38Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2018-06-29T14:31:43.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseStackdriverJsonDuopullBypass() throws Exception {
    String buf =
        "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_"
            + "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\":"
            + "\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"999999999"
            + "9999999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance"
            + "\"},\"jsonPayload\":{\"EnvVersion\": \"2.0\", \"Severity\": 6, \"Fields\""
            + ": {\"event_description_valid_secs\": 3600, \"event_description_count\": 1, "
            + "\"event_description_user_id\": \"ZZZZZZZZZZZZZZZZZZZZ\", \"event_object\": \"worf\""
            + ", \"event_timestamp\": 1530282703, \"event_username\": \"First Last\", "
            + "\"event_description_bypass_code_ids\": [\"XXXXXXXXXXXXXXXXXXXX\"], \"event_description_by"
            + "pass\": \"\", \"path\": \"/admin/v1/logs/administrator\", \"msg\": "
            + "\"duopull event\", \"event_action\": \"bypass_create\", "
            + "\"event_description_auto_generated\": true, \"event_description_remaining_uses\": 1}, \"Hostname\": \"test"
            + "\", \"Pid\": 62312, \"Time\": \"2018-07-04T15:49:46Z\", \"Logger\": "
            + "\"duopull\", \"Type\": \"app.log\", \"Timestamp\": 1530719386349480000},\"timestamp\":\"2018-09-18T22:15:38Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2018-06-29T14:31:43.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseStackdriverJsonDuopullAuthV2() throws Exception {
    String buf =
        "{\"insertId\": \"18osuk3fbh39dp\",\"jsonPayload\": {\"Fields\":"
            + "{\"event_access_device_hostname\": null,\"event_access_device_location_city\":"
            + "\"woff\",\"event_user_key\": \"xxxxxx\",\"path\": \"/admin/v2/logs/authentication\","
            + "\"event_auth_device_location_state\": \"worf\",\"event_application_name\": "
            + "\"access\",\"event_access_device_location_country\": \"nation state\","
            + "\"event_application_key\": \"xxxxxxxx\",\"msg\": \"duopull event\","
            + "\"event_auth_device_location_country\": \"nation state\",\"event_auth_device_ip\": "
            + "\"127.0.0.1\",\"event_timestamp\": 1556134128,\"event_event_type\": "
            + "\"authentication\",\"event_factor\": \"duo_push\",\"event_access_device_location_state\": "
            + "\"worf\",\"event_result\": \"success\",\"event_auth_device_name\": "
            + "\"555-555-5555\",\"event_txid\": \"4a8293de-df14-4a7a-98ae-8ed36f155853\","
            + "\"event_user_name\": \"doggo\",\"event_reason\": \"user_approved\","
            + "\"event_auth_device_location_city\": \"worf\",\"event_access_device_ip\": "
            + "\"127.0.0.1\"},\"Hostname\": \"localhost\",\"Pid\": 1,\"EnvVersion\": "
            + "\"2.0\",\"Type\": \"app.log\",\"Timestamp\": 1556134201997608700,"
            + "\"Severity\": 6,\"Logger\": \"duopull\",\"Time\": \"2019-04-24T19:30:01Z\"},"
            + "\"resource\": {\"type\": \"project\",\"labels\": {\"project_id\": \"pipeline\"}},"
            + "\"timestamp\": \"2019-04-24T19:30:01.997770950Z\",\"logName\": \"projects/pipeline/logs/duopull\","
            + "\"receiveTimestamp\": \"2019-04-24T19:30:02.013133847Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2019-04-24T19:28:48.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("doggo", data.getEventUsername());
    assertEquals("user_approved", data.getEventReason());
    assertEquals("/admin/v2/logs/authentication", data.getPath());
  }

  @Test
  public void testParseStackdriverJsonDuopullAdminLogin() throws Exception {
    String buf =
        "{\"insertId\": \"gh39djdfyz4lya\",\"jsonPayload\": {\"Fields\": {\"event_object\": null,"
            + "\"event_username\": \"riker\",\"event_description_factor\": \"push\",\"msg\": \"duopull event\","
            + "\"event_timestamp\": 1556216112,\"event_description_device\": \"555-555-5555\","
            + "\"event_action\": \"admin_login\",\"event_description_primary_auth_method\": \"Password\","
            + "\"path\": \"/admin/v1/logs/administrator\",\"event_description_ip_address\": \"127.0.0.1\""
            + "},\"Pid\": 1,\"Hostname\": \"localhost\","
            + "\"EnvVersion\": \"2.0\",\"Type\": \"app.log\",\"Timestamp\": 1556216660526927000,"
            + "\"Severity\": 6,\"Logger\": \"duopull\",\"Time\": \"2019-04-25T18:24:20Z\"},"
            + "\"resource\": {\"type\": \"project\",\"labels\": {\"project_id\": \"pipeline\"}},"
            + "\"timestamp\": \"2019-04-25T18:24:20.527024712Z\","
            + "\"logName\": \"projects/pipeline/logs/duopull\","
            + "\"receiveTimestamp\": \"2019-04-25T18:24:20.555273442Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    assertEquals("2019-04-25T18:15:12.000Z", e.getTimestamp().toString());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertNotNull(data);
    assertEquals("riker", data.getEventUsername());
    assertEquals("127.0.0.1", data.getEventDescriptionIpAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());
    assertEquals("duo_admin_login", n.getObject());
  }

  @Test
  public void testParseAmoDockerAmoLogin() throws Exception {
    String buf =
        "{\"Timestamp\": 1559088435038770944, \"Type\": \"z.users\", \"Logger\": \"http_app_"
            + "addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \"EnvVersion\": \"2.0\","
            + " \"Severity\": 7, \"Pid\": 3435, \"Fields\": {\"uid\": \"<anon>\", \"remoteAddressCh"
            + "ain\": \"216.160.83.56\", \"msg\": \"User (00000000: username-0000000000000000000000000000"
            + "0000) logged in successfully\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.LOGIN, d.getEventType());
    assertEquals("username-00000000000000000000000000000000", d.getUid());
    assertEquals("216.160.83.56", d.getRemoteIp());
    assertEquals(
        "User (00000000: username-00000000000000000000000000000000) logged in successfully",
        d.getMsg());
  }

  @Test
  public void testParseAmoDockerAmoStackdriverLogin() throws Exception {
    String buf =
        "{\"insertId\":\"11111111111111\",\"jsonPayload\":{\"Fields\":{\"remoteAddress"
            + "Chain\":\"1.2.3.4\",\"uid\":\"<anon>\",\"msg\":\"User (00000000: User Name) l"
            + "ogged in successfully\"},\"Hostname\":\"ip\",\"Pid\":11,\"Type\":\"z.users\","
            + "\"EnvVersion\":\"2.0\",\"Timestamp\":1562336365437102300,\"Severity\":7,\"Log"
            + "ger\":\"http_app_addons_stage\"},\"resource\":{\"type\":\"aws_ec2_instance\","
            + "\"labels\":{\"project_id\":\"moz\",\"region\":\"aws:us-east-1c\",\"aws_accoun"
            + "t\":\"000000000000\",\"instance_id\":\"i-00000000000000000\"}},\"timestamp\""
            + ":\"2019-07-05T14:19:25.437873149Z\",\"labels\":{\"stack\":\"amostage1\",\"ap"
            + "plication\":\"amo\",\"type\":\"olympia_internal\",\"env\":\"stage\",\"ec2.am"
            + "azonaws.com/resource_name\":\"ip\"},\"logName\":\"projects/moz/logs/docker.a"
            + "mo-olympia_internal.addons-internal\",\"receiveTimestamp\":\"2019-07-05T14:1"
            + "9:28.125276392Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.LOGIN, d.getEventType());
    assertEquals("User Name", d.getUid());
    assertEquals("1.2.3.4", d.getRemoteIp());
    assertEquals("User (00000000: User Name) logged in successfully", d.getMsg());
  }

  @Test
  public void testParseAmoDockerAmoNewVersion() throws Exception {
    String buf =
        "{\"Timestamp\": 1559088455564122624, \"Type\": \"z.versions\", \"Logger\": \"http_"
            + "app_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \"EnvVersion\": \"2"
            + ".0\", \"Severity\": 6, \"Pid\": 3379, \"Fields\": {\"uid\": \"devinoni_ral\""
            + ", \"remoteAddressChain\": \"216.160.83.56\", \"msg\": \"New version: <Version:"
            + " 1.0.0> (0000000) from <FileUpload: 00000000000000000000000000000000>\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.NEWVERSION, d.getEventType());
    assertEquals("devinoni_ral", d.getUid());
    assertEquals("216.160.83.56", d.getRemoteIp());
    assertEquals(
        "New version: <Version: 1.0.0> (0000000) from <FileUpload: 00000000000000000000000000000000>",
        d.getMsg());
    assertEquals("1.0.0", d.getAddonVersion());
    assertEquals("0000000", d.getAddonId());
  }

  @Test
  public void testParseAmoUploadMnt() throws Exception {
    String buf =
        "{\"Timestamp\": 1562177982234531072, \"Type\": \"z.files\", \"Logger\": \"http_ap"
            + "p_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \"EnvVersion\": \"2."
            + "0\", \"Severity\": 6, \"Pid\": 3326, \"Fields\": {\"uid\": \"anonymous\", \"remot"
            + "eAddressChain\": \"216.160.83.56\", \"msg\": \"UPLOAD: 'filename.zip' (10000 byte"
            + "s) to '/mnt/efs/addons.mozilla.org/files/temp/00000000000000000000000000000000.xpi'\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.FILEUPLOADMNT, d.getEventType());
    assertEquals("filename.zip", d.getFileName());
    assertEquals(10000, (int) d.getBytes());
  }

  @Test
  public void testParseAmoDockerAmoFileUpload() throws Exception {
    String buf =
        "{\"Timestamp\": 1561211871139126528, \"Type\": \"z\", \"Logger\": \"htt"
            + "p_app_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", "
            + "\"EnvVersion\": \"2.0\", \"Severity\": 6, \"Pid\": 5190, \"Fields\": {\"uid\":"
            + " \"devinoni_ral\", \"remoteAddressChain\": \"216.160.83.56\", \"msg\": \"FileUp"
            + "load created: 00000000000000000000000000000000\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.FILEUPLOAD, d.getEventType());
    assertEquals("devinoni_ral", d.getUid());
    assertEquals("216.160.83.56", d.getRemoteIp());
    assertEquals("FileUpload created: 00000000000000000000000000000000", d.getMsg());
  }

  @Test
  public void testParseAmoGotProfile() throws Exception {
    String buf =
        "{\"Timestamp\": 1559088104777733120, \"Type\": \"accounts.verify\", \"Logger\":"
            + " \"http_app_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \"EnvVers"
            + "ion\": \"2.0\", \"Severity\": 7, \"Pid\": 3415, \"Fields\": {\"uid\": \"<anon>\""
            + ", \"remoteAddressChain\": \"216.160.83.56\", \"msg\": \"Got profile {'email': 'riker@m"
            + "ozilla.com', 'locale': 'en,en-US', 'amrValues': ['pwd', 'email'], 'twoFactorAuth"
            + "entication': False, 'uid': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'avatar': 'https:"
            + "//firefoxusercontent.com/00000000000000000000000000000000', 'avatarDefault': Tru"
            + "e} [0000000000000000000000000000000000000000000000000000000000000000]\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.GOTPROFILE, d.getEventType());
    assertEquals("riker@mozilla.com", d.getFxaEmail());
    assertEquals("216.160.83.56", d.getRemoteIp());
  }

  @Test
  public void testParseAmoRestrictedEmail() throws Exception {
    String buf =
        "{\"Timestamp\": 1560523200813063936, \"Type\": \"z.users\", \"Logger\": \"http"
            + "_app_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \""
            + "EnvVersion\": \"2.0\", \"Severity\": 6, \"Pid\": 578, \"Fields\": {\"uid\": \"a"
            + "nonymous\", \"remoteAddressChain\": \"216.160.83."
            + "56\", \"msg\": \"Restricting request from email riker"
            + "@mozilla.com (reputation=0)\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.RESTRICTED, d.getEventType());
    assertEquals("riker@mozilla.com", d.getRestrictedValue());
    assertEquals("216.160.83.56", d.getRemoteIp());
  }

  @Test
  public void testParseAmoRestrictedIp() throws Exception {
    String buf =
        "{\"Timestamp\": 1560523200813063936, \"Type\": \"z.users\", \"Logger\": \"http"
            + "_app_addons\", \"Hostname\": \"ip.us-west-2.compute.internal\", \""
            + "EnvVersion\": \"2.0\", \"Severity\": 6, \"Pid\": 578, \"Fields\": {\"uid\": \"a"
            + "nonymous\", \"remoteAddressChain\": \"216.160.83."
            + "56\", \"msg\": \"Restricting request from ip 216.160.83.56"
            + " (reputation=49)\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AMODOCKER, e.getPayloadType());
    AmoDocker d = e.getPayload();
    assertNotNull(d);
    assertEquals(AmoDocker.EventType.RESTRICTED, d.getEventType());
    assertEquals("216.160.83.56", d.getRestrictedValue());
    assertEquals("216.160.83.56", d.getRemoteIp());
  }

  @Test
  public void testParseAlert() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"3ddcbcff-f334-4189-953c-14a34a2cc030\",\"summa"
            + "ry\":\"test suspicious account creation, 216.160.83.56 3\",\"category\":\"cust"
            + "oms\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":[{\"key\":\"noti"
            + "fy_merge\",\"value\":\"account_creation_abuse\"},{\"key\":\"customs_category\""
            + ",\"value\":\"account_creation_abuse\"},{\"key\":\"sourceaddress\",\"value\":\""
            + "216.160.83.56\"},{\"key\":\"count\",\"value\":\"3\"},{\"key\":\"email\",\"valu"
            + "e\":\"user@mail.com, user.1@mail.com, user.1.@mail.com\"}]}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.ALERT, e.getPayloadType());
    Alert d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.alert.Alert a = d.getAlert();
    assertNotNull(a);
    assertEquals("test suspicious account creation, 216.160.83.56 3", a.getSummary());
    assertEquals("customs", a.getCategory());
    assertEquals("216.160.83.56", a.getMetadataValue("sourceaddress"));
  }

  @Test
  public void testParseTaskcluster() throws Exception {
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fields"
            + "\":{\"apiVersion\":\"v1\",\"clientId\":\"mozilla-auth0/ad|Mozilla-LDAP|riker/servi"
            + "ces\",\"duration\":20159.035803,\"expires\":\"3017-02-01T05:00:00.000Z\",\"hasAuth"
            + "ed\":true,\"method\":\"POST\",\"name\":\"claimWork\",\"public\":false,\"resource\""
            + ":\"/v1/claim-work/test-provisioner/macos-workers\",\"satisfyingScopes\":[\"queue:c"
            + "laim-work:test-provisioner/macos-workers\",\"queue:worker-id:test-worker-group/test\""
            + "],\"sourceIp\":\"216.160.83.56\",\"statusCode\":200,\"v\":1},\"Hostname\":\"000000"
            + "00-0000-0000-0000-000000000000\",\"Logger\":\"taskcluster.queue.api\",\"Pid\":37,\""
            + "Severity\":5,\"Timestamp\":1558469098790000000,\"Type\":\"monitor.apiMethod\",\"ser"
            + "viceContext\":{\"service\":\"queue\",\"version\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            + "aaaaaaaa\"}},\"labels\":{\"compute.googleapis.com/resource_name\":\"00000000-0000-0"
            + "000-0000-000000000000\"},\"logName\":\"projects/logging/logs/queue\",\"receiveTimes"
            + "tamp\":\"2019-05-21T20:05:00.544662934Z\",\"resource\":{\"labels\":{\"instance_id\""
            + ":\"test\",\"project_id\":\"test-logging\",\"zone\":\"test\"},\"type\":\"gce_instanc"
            + "e\"},\"severity\":\"NOTICE\",\"timestamp\":\"2019-05-21T20:04:58.790308Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.TASKCLUSTER, e.getPayloadType());
    Taskcluster d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.taskcluster.Taskcluster data = d.getTaskclusterData();
    assertNotNull(data);
    assertEquals("mozilla-auth0/ad|Mozilla-LDAP|riker/services", data.getClientId());
    assertEquals(20159.03, (double) data.getDuration(), 0.5);
    assertEquals("3017-02-01T05:00:00.000Z", data.getExpires());
    assertTrue(data.getHasAuthed());
    assertEquals("216.160.83.56", data.getSourceIp());
    assertEquals(200, (int) data.getStatusCode());
    assertEquals("riker", d.getResolvedSubject());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH_SESSION));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
    assertEquals(47.25, n.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, n.getSourceAddressLongitude(), 0.5);
    assertEquals("taskcluster-/v1/claim-work/test-provisioner/macos-workers", n.getObject());
  }

  @Test
  public void testParseISO8601() throws Exception {
    String[] datelist = {
      "2018-09-28T18:55:12.469",
      "2018-09-28T18:55:12.469Z",
      "2018-09-28T18:55:12.469+00:00",
      "2018-09-28T18:55:12.469373944Z",
      "2018-09-28T18:55:12.469373944+00:00"
    };
    Long m = 1538160912469L;

    for (String t : datelist) {
      Long d = Parser.parseISO8601(t).getMillis();
      assertEquals(m, d);
    }
    assertEquals(1000L, Parser.parseISO8601("1970-01-01T00:00:01+00:00").getMillis());
    assertEquals(1000L, Parser.parseISO8601("1970-01-01T00:00:01").getMillis());
    assertNull(Parser.parseISO8601("not a date"));
    assertNull(Parser.parseISO8601("1970-01-01T00:00:00.00000000000000000000"));
  }

  @Test
  public void testParserFastMatcher() throws Exception {
    ParserCfg cfg = new ParserCfg();
    cfg.setParserFastMatcher("picard");

    Parser p = new Parser(cfg);

    assertNull(p.parse("riker test"));
    assertNotNull(p.parse("picard test"));
  }

  @Test
  public void testParserMaxTimeDifference() throws Exception {
    String bufPre =
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
            + ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"";
    String bufPost = "\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA" + "AAAAAAAAAA\"}";

    DateTimeFormatter dtf = DateTimeFormat.forPattern("yyyy-MM-dd'T'HH:mm:ss.000000000'Z'");
    DateTime now = new DateTime(DateTimeZone.UTC);

    String buf = bufPre + dtf.print(now) + bufPost;
    String bufOld = bufPre + dtf.print(now.minusMinutes(30)) + bufPost;

    ParserCfg cfg = new ParserCfg();
    Parser p = new Parser(cfg);
    assertNotNull(p.parse(buf));
    assertNotNull(p.parse(bufOld));

    cfg.setMaxTimestampDifference(300);
    p = new Parser(cfg);
    assertNotNull(p.parse(buf));
    Boolean af = false;
    try {
      p.parse(bufOld);
    } catch (Parser.EventTooOldException exc) {
      af = true;
    }
    assertTrue(af);
  }

  @Test
  public void testHTTPMultiAddressSelector() throws Exception {
    ParserCfg cfg = new ParserCfg();

    assertEquals("1.1.1.1", new Parser(cfg).applyXffAddressSelector("1.1.1.1"));
    assertNull(new Parser(cfg).applyXffAddressSelector("test"));
    assertNull(new Parser(cfg).applyXffAddressSelector("test, 1.1.1.1"));
    assertEquals("1.1.1.1", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 1.1.1.1"));

    ArrayList<String> n = new ArrayList<>();
    n.add("1.1.1.0/24");
    n.add("10.0.0.1/32");
    cfg.setXffAddressSelector(n);

    assertEquals("2.2.2.2", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 1.1.1.10"));
    assertEquals(
        "2.2.2.2", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 1.1.1.200, 1.1.1.10"));
    assertEquals(
        "2.2.2.2", new Parser(cfg).applyXffAddressSelector("1.1.1.200, 2.2.2.2, 1.1.1.10"));
    assertEquals("2.2.2.2", new Parser(cfg).applyXffAddressSelector("::1, 2.2.2.2, 1.1.1.10"));
    // All match selector, return last
    assertEquals(
        "1.1.1.1", new Parser(cfg).applyXffAddressSelector("1.1.1.200, 1.1.1.10, 1.1.1.1"));

    assertEquals("2.2.2.2", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 10.0.0.1"));
    assertEquals("10.0.0.0", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 10.0.0.0"));

    n.add("2001:db8:1234::/48");
    cfg.setXffAddressSelector(n);

    assertEquals("2.2.2.2", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 2001:db8:1234::1"));
    assertEquals(
        "2001:db8:1235::1", new Parser(cfg).applyXffAddressSelector("2.2.2.2, 2001:db8:1235::1"));
  }

  @Test
  public void testParseXForwardedFor() throws Exception {
    String[] result = Parser.parseXForwardedFor("0.0.0.0");
    assertEquals(1, result.length);
    assertEquals("0.0.0.0", result[0]);

    result = Parser.parseXForwardedFor("0.0.0.0,1.1.1.1");
    assertEquals(2, result.length);
    assertEquals("0.0.0.0", result[0]);
    assertEquals("1.1.1.1", result[1]);

    result = Parser.parseXForwardedFor("0.0.0.0, 1.1.1.1, 2.2.2.2");
    assertEquals(3, result.length);
    assertEquals("0.0.0.0", result[0]);
    assertEquals("1.1.1.1", result[1]);
    assertEquals("2.2.2.2", result[2]);

    result = Parser.parseXForwardedFor("");
    assertEquals(0, result.length);

    result = Parser.parseXForwardedFor(null);
    assertNull(result);

    result = Parser.parseXForwardedFor("0.0.0.0, test");
    assertNull(result);

    result = Parser.parseXForwardedFor("test");
    assertNull(result);

    result = Parser.parseXForwardedFor("0.0.0.0, 1.2.3.999");
    assertNull(result);
  }

  @Test
  public void testCloudtrailRawAction() throws Exception {
    String buf =
        "{\"eventVersion\": \"1.02\",\"userIdentity\": {\"type\": "
            + "\"IAMUser\",\"principalId\": \"XXXXXXXXXXXXXXXXXXXXX\",\"arn\": "
            + "\"arn:aws:iam::XXXXXXXXXXXX:user/uhura\",\"accountId\": \"XXXXXXXXXXXX\","
            + "\"accessKeyId\": \"XXXXXXXXXXXX\",\"userName\": \"uhura\",\"sessionContext\": "
            + "{\"attributes\": {\"mfaAuthenticated\": \"true\",\"creationDate\": "
            + "\"2018-07-02T18:14:11Z\"}},\"invokedBy\": \"signin.amazonaws.com\"},\"eventTime\": "
            + "\"2018-07-02T18:20:04Z\",\"eventSource\": \"iam.amazonaws.com\",\"eventName\": "
            + "\"CreateAccessKey\",\"awsRegion\": \"us-east-1\",\"sourceIPAddress\": \"127.0.0.1\","
            + "\"userAgent\": \"signin.amazonaws.com\",\"requestParameters\": {\"userName\": \"guinan\"},"
            + "\"responseElements\": {\"accessKey\": {\"accessKeyId\": \"XXXXXXXXXXXXXXX\","
            + "\"status\": \"Active\",\"userName\": \"guinan\",\"createDate\": "
            + "\"Jul 2, 2018 6:20:04 PM\"}},\"requestID\": \"8abc0444-7e24-11e8-f2fa-9d71c95ef006\","
            + "\"eventID\": \"55555343-132e-43bb-8d5d-23d0ef81178e\",\"eventType\": "
            + "\"AwsApiCall\",\"recipientAccountId\": \"1234567890\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2018-07-02T18:20:04.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("uhura", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
  }

  @Test
  public void testCloudtrailRawConsoleAuth() throws Exception {
    String buf =
        "{\"awsRegion\":\"us-west-2\",\"eventID\": "
            + "\"00000000-0000-0000-0000-000000000000\",\"eventName\":\"ConsoleLogin\", "
            + "\"eventSource\":\"signin.amazonaws.com\",\"eventTime\":\"2018-06-26T06:00:13Z\", "
            + "\"eventType\":\"AwsConsoleSignIn\",\"eventVersion\":\"1.05\", "
            + "\"recipientAccountId\":\"999999999999\",\"responseElements\": "
            + "{\"ConsoleLogin\":\"Success\"},\"sourceIPAddress\":\"127.0.0.1\",\"userAgent\": "
            + "\"Mozilla/5.0(Macintosh;IntelMacOSX10.13;rv:62.0)Gecko/20100101Firefox/62.0\", "
            + "\"userIdentity\":{\"accountId\":\"999999999999\",\"arn\": "
            + "\"arn:aws:iam::999999999999:user/riker\",\"principalId\":\"XXXXXXXXXXXXXXXXXXXXX\", "
            + "\"type\":\"IAMUser\",\"userName\":\"riker\",\"sessionContext\": {\"attributes\": "
            + "{\"mfaAuthenticated\": \"true\",\"creationDate\": \"2018-07-02T18:14:11Z\"}}}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2018-06-26T06:00:13.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("riker", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());
    assertEquals("999999999999", n.getObject());
  }

  @Test
  public void testCloudtrailRawAssumeRole() throws Exception {
    String buf =
        "{\"eventVersion\": \"1.05\",\"userIdentity\": {\"type\": \"IAMUser\","
            + "\"principalId\": \"XXXXXXXXXXXX\",\"arn\": \"arn:aws:iam::XXXXXXXXXX:user/riker\","
            + "\"accountId\": \"XXXXXXXXXXXXX\",\"accessKeyId\": \"XXXXXXXXX\",\"userName\": "
            + "\"riker\",\"sessionContext\": {\"attributes\": {\"mfaAuthenticated\": \"true\","
            + "\"creationDate\": \"2018-08-14T23:22:18Z\"}},\"invokedBy\": \"signin.amazonaws.com\"},"
            + "\"eventTime\": \"2018-10-25T01:23:46Z\",\"eventSource\": \"sts.amazonaws.com\","
            + "\"eventName\": \"AssumeRole\",\"awsRegion\": \"us-east-1\",\"sourceIPAddress\": "
            + "\"127.0.0.1\",\"userAgent\": \"signin.amazonaws.com\",\"eventID\": "
            + "\"000000000-000000\",\"eventType\": \"AwsApiCall\",\"recipientAccountId\": \"XXXXXXXX\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2018-10-25T01:23:46.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("riker", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("127.0.0.1", n.getSourceAddress());
    assertEquals("XXXXXXXX", n.getObject());
  }

  @Test
  public void testCloudtrailStackdriverAuthConsoleLogin() throws Exception {
    String buf =
        "{\"insertId\": \"x1958zfskvv0x\", \"jsonPayload\": "
            + "{ \"eventID\": \"55555555-3998-4e79-abdc-4c67df8bd013\", "
            + "\"userIdentity\": { \"principalId\": \"XXXXXXXXXXXXXXX\", "
            + "\"accountId\": \"123456789\", \"userName\": \"uhura\", "
            + "\"type\": \"IAMUser\", \"arn\": \"arn:aws:iam::123456789:user/uhura\" },"
            + "\"eventTime\": \"2019-03-05T20:54:57Z\", \"responseElements\": {\"ConsoleLogin\": "
            + "\"Success\"},\"additionalEventData\": {\"MobileVersion\": "
            + "\"No\",\"MFAUsed\": \"Yes\",\"LoginTo\": \"XXXXXX\"},"
            + "\"eventVersion\": \"1.05\",\"eventName\": \"ConsoleLogin\",\"userAgent\": "
            + "\"Mozilla/XXX\",\"awsRegion\": \"us-east-1\", "
            + "\"requestParameters\": null, \"eventType\": \"AwsConsoleSignIn\", "
            + "\"eventSource\": \"signin.amazonaws.com\", \"recipientAccountId\": "
            + "\"123456789\", \"sourceIPAddress\": \"127.0.0.1\"},\"resource\": "
            + "{\"type\": \"project\",\"labels\": {\"project_id\": \"xxxx\"}}, "
            + "\"timestamp\": \"2019-03-05T21:03:08.738216017Z\",\"logName\": "
            + "\"cloudtrail\",\"receiveTimestamp\": \"2019-03-05T21:03:11.314310240Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2019-03-05T20:54:57.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("uhura", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("127.0.0.1", n.getSourceAddress());
    assertEquals("123456789", n.getObject());
  }

  @Test
  public void testCloudtrailStackdriverAuthAssumeRole() throws Exception {
    String buf =
        "{\"insertId\": \"ak64xfucxo62\",\"jsonPayload\": {\"responseElements\": "
            + "{\"credentials\": {\"expiration\": \"Mar 15, 2015 1:38:03 PM\","
            + "\"accessKeyId\": \"ACCESSKEY\",\"sessionToken\": \"XXXXXXX\"},"
            + "\"assumedRoleUser\": {\"assumedRoleId\": \"ABCD:uhura\",\"arn\": "
            + "\"arn:aws:sts::987654321:assumed-role/role/uhura\"}},\"eventVersion\": "
            + "\"1.05\",\"eventName\": \"AssumeRole\",\"userAgent\": "
            + "\"signin.amazonaws.com\",\"requestParameters\": {\"roleArn\": "
            + "\"arn:aws:iam::987654321:role/role\",\"roleSessionName\": "
            + "\"uhura\"},\"awsRegion\": \"us-east-1\",\"eventType\": \"AwsApiCall\","
            + "\"sharedEventID\": \"555555-5727-4be3-b20c\",\"eventSource\": "
            + "\"sts.amazonaws.com\",\"resources\": [{\"ARN\": "
            + "\"arn:aws:iam::987654321:role/role\",\"accountId\": "
            + "\"987654321\",\"type\": \"AWS::IAM::Role\"}],\"recipientAccountId\": "
            + "\"1234567890\",\"sourceIPAddress\": \"10.0.0.1\",\"requestID\": "
            + "\"555555-3f5e-11e9-a09a\",\"eventID\": "
            + "\"5555555-3f0d-4cc3-b979\",\"userIdentity\": "
            + "{\"sessionContext\": {\"attributes\": {\"creationDate\": "
            + "\"2019-03-05T15:47:59Z\",\"mfaAuthenticated\": \"true\"}},"
            + "\"principalId\": \"PRINCIPALID\",\"accessKeyId\": \"ACCESSKEY\","
            + "\"userName\": \"uhura\",\"accountId\": \"1234567890\",\"type\": "
            + "\"IAMUser\",\"invokedBy\": \"signin.amazonaws.com\",\"arn\": "
            + "\"arn:aws:iam::1234567890:user/uhura\"},\"eventTime\": "
            + "\"2011-12-04T15:48:13Z\"},\"resource\": {\"type\": \"project\","
            + "\"labels\": {\"project_id\": \"foxsec-pipeline-ingestion\"}},"
            + "\"timestamp\": \"2015-03-15T15:58:52.211925220Z\",\"logName\": "
            + "\"cloudtrail\",\"receiveTimestamp\": \"2018-01-01T15:58:53.115974226Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2011-12-04T15:48:13.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("uhura", ct.getUser());
    assertEquals("10.0.0.1", ct.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("10.0.0.1", n.getSourceAddress());
    assertEquals("1234567890", n.getObject());
  }

  @Test
  public void testCloudtrailStackdriverAction() throws Exception {
    String buf =
        "{\"insertId\": \"1culjbag27h3ns1\",\"jsonPayload\": {\"eventVersion\": "
            + "\"1.02\",\"userIdentity\": {\"type\": "
            + "\"IAMUser\",\"principalId\": \"XXXXXXXXXXXXXXXXXXXXX\",\"arn\": "
            + "\"arn:aws:iam::XXXXXXXXXXXX:user/uhura\",\"accountId\": \"XXXXXXXXXXXX\","
            + "\"accessKeyId\": \"XXXXXXXXXXXX\",\"userName\": \"uhura\",\"sessionContext\": "
            + "{\"attributes\": {\"mfaAuthenticated\": \"true\",\"creationDate\": "
            + "\"2018-07-02T18:14:11Z\"}},\"invokedBy\": \"signin.amazonaws.com\"},\"eventTime\": "
            + "\"2018-07-02T18:20:04Z\",\"eventSource\": \"iam.amazonaws.com\",\"eventName\": "
            + "\"CreateAccessKey\",\"awsRegion\": \"us-east-1\",\"sourceIPAddress\": \"127.0.0.1\","
            + "\"userAgent\": \"signin.amazonaws.com\",\"requestParameters\": {\"userName\": \"guinan\"},"
            + "\"responseElements\": {\"accessKey\": {\"accessKeyId\": \"XXXXXXXXXXXXXXX\","
            + "\"status\": \"Active\",\"userName\": \"guinan\",\"createDate\": "
            + "\"Jul 2, 2018 6:20:04 PM\"}},\"requestID\": \"8abc0444-7e24-11e8-f2fa-9d71c95ef006\","
            + "\"eventID\": \"55555343-132e-43bb-8d5d-23d0ef81178e\",\"eventType\": "
            + "\"AwsApiCall\",\"recipientAccountId\": \"1234567890\"}, \"resource\": { \"type\": "
            + "\"project\", \"labels\": {\"project_id\": \"sandbox\"}}, \"timestamp\": "
            + "\"2018-10-11T18:41:09.542038318Z\", \"logName\": \"projects/sandbox/logs/ctstreamer\", "
            + "\"receiveTimestamp\": \"2018-10-11T18:41:12.665161934Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    assertEquals("2018-07-02T18:20:04.000Z", e.getTimestamp().toString());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("uhura", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
  }

  @Test
  public void testParseGuardDutyFinding() throws Exception {
    String buf =
        "{\"schemaVersion\":\"2.0\",\"accountId\":\"123456789012\",\"region\":\"us-west-2\","
            + "\"partition\":\"aws\",\"id\":\"591f8d2ed2edaf6a96ad486b59ed8428\","
            + "\"arn\":\"arn:aws:guardduty:us-west-2:123456789012:detector/cab59ed1d9760dbaa8930337156d4547/finding/56b59ed2edaf6a84291f8d2ed96ad488\","
            + "\"type\":\"Recon:IAMUser/UserPermissions\","
            + "\"resource\":{\"resourceType\":\"AccessKey\",\"accessKeyDetails\":{\"accessKeyId\":\"GeneratedFindingAccessKeyId\","
            + "\"principalId\":\"GeneratedFindingPrincipalId\",\"userType\":\"IAMUser\",\"userName\":\"GeneratedFindingUserName\"}},"
            + "\"service\":{\"serviceName\":\"guardduty\",\"detectorId\":\"cab59ed1d9760dbaa8930337156d4547\","
            + "\"action\":{\"actionType\":\"AWS_API_CALL\",\"awsApiCallAction\":{\"api\":\"GeneratedFindingAPIName\","
            + "\"serviceName\":\"GeneratedFindingAPIServiceName\",\"callerType\":\"Remote IP\",\"remoteIpDetails\":{\"ipAddressV4\":\"198.51.100.0\","
            + "\"organization\":{\"asn\":\"-1\",\"asnOrg\":\"GeneratedFindingASNOrg\",\"isp\":\"GeneratedFindingISP\",\"org\":\"GeneratedFindingORG\"},"
            + "\"country\":{\"countryName\":\"GeneratedFindingCountryName\"},\"city\":{\"cityName\":\"GeneratedFindingCityName\"},"
            + "\"geoLocation\":{\"lat\":0,\"lon\":0}},\"affectedResources\":{}}},\"resourceRole\":\"TARGET\","
            + "\"additionalInfo\":{\"recentApiCalls\":[{\"api\":\"GeneratedFindingAPIName1\",\"count\":2},{\"api\":\"GeneratedFindingAPIName2\","
            + "\"count\":2}],\"sample\":true},\"eventFirstSeen\":\"2019-06-09T19:10:08.222Z\",\"eventLastSeen\":\"2019-06-09T19:10:23.301Z\","
            + "\"archived\":false,\"count\":2},\"severity\":5,\"createdAt\":\"2019-06-09T19:10:08.222Z\",\"updatedAt\":\"2019-06-09T19:10:23.301Z\","
            + "\"title\":\"Unusual user permission reconnaissance activity by GeneratedFindingUserName.\","
            + "\"description\":\"APIs commonly used to discover the users, groups, policies and permissions in an account,"
            + " was invoked by IAM principal GeneratedFindingUserName under unusual circumstances. "
            + "Such activity is not typically seen from this principal.\"}";

    Parser p = getTestParser();
    assertNotNull(p);

    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GUARDDUTY, e.getPayloadType());

    GuardDuty gde = e.getPayload();
    assertNotNull(gde);

    Finding gdf = gde.getFinding();
    assertNotNull(gdf);

    assertEquals("2.0", gdf.getSchemaVersion());
    assertEquals("123456789012", gdf.getAccountId());
    assertEquals("us-west-2", gdf.getRegion());
    assertEquals("aws", gdf.getPartition());
    assertEquals("591f8d2ed2edaf6a96ad486b59ed8428", gdf.getId());
    assertEquals(
        "arn:aws:guardduty:us-west-2:123456789012:detector/cab59ed1d9760dbaa8930337156d4547/finding/56b59ed2edaf6a84291f8d2ed96ad488",
        gdf.getArn());
    assertEquals("Recon:IAMUser/UserPermissions", gdf.getType());
    assertEquals(5.0, gdf.getSeverity(), 0.0);
    assertEquals("2019-06-09T19:10:08.222Z", gdf.getCreatedAt());
    assertEquals("2019-06-09T19:10:23.301Z", gdf.getUpdatedAt());
    assertEquals(
        "Unusual user permission reconnaissance activity by GeneratedFindingUserName.",
        gdf.getTitle());
    assertEquals(
        "APIs commonly used to discover the users, groups, policies and permissions in an account, was invoked by IAM principal GeneratedFindingUserName under unusual circumstances. Such activity is not typically seen from this principal.",
        gdf.getDescription());
  }

  @Test
  public void testParseGuardDutyFindingWithCloudWatchEventWrapper() throws Exception {
    String buf =
        "{\"version\": \"0\", \"id\": \"c8c4daa7-a20c-2f03-0070-b7393dd542ad\","
            + "\"detail-type\": \"GuardDuty Finding\", \"source\": \"aws.guardduty\",\"account\": \"123456789012\","
            + " \"time\": \"1970-01-01T00:00:00Z\", \"region\": \"us-west-2\", \"resources\": [],"
            + " \"detail\": "
            + "{\"schemaVersion\":\"2.0\",\"accountId\":\"123456789012\",\"region\":\"us-west-2\","
            + "\"partition\":\"aws\",\"id\":\"591f8d2ed2edaf6a96ad486b59ed8428\","
            + "\"arn\":\"arn:aws:guardduty:us-west-2:123456789012:detector/cab59ed1d9760dbaa8930337156d4547/finding/56b59ed2edaf6a84291f8d2ed96ad488\","
            + "\"type\":\"Recon:IAMUser/UserPermissions\","
            + "\"resource\":{\"resourceType\":\"AccessKey\",\"accessKeyDetails\":{\"accessKeyId\":\"GeneratedFindingAccessKeyId\","
            + "\"principalId\":\"GeneratedFindingPrincipalId\",\"userType\":\"IAMUser\",\"userName\":\"GeneratedFindingUserName\"}},"
            + "\"service\":{\"serviceName\":\"guardduty\",\"detectorId\":\"cab59ed1d9760dbaa8930337156d4547\","
            + "\"action\":{\"actionType\":\"AWS_API_CALL\",\"awsApiCallAction\":{\"api\":\"GeneratedFindingAPIName\","
            + "\"serviceName\":\"GeneratedFindingAPIServiceName\",\"callerType\":\"Remote IP\",\"remoteIpDetails\":{\"ipAddressV4\":\"198.51.100.0\","
            + "\"organization\":{\"asn\":\"-1\",\"asnOrg\":\"GeneratedFindingASNOrg\",\"isp\":\"GeneratedFindingISP\",\"org\":\"GeneratedFindingORG\"},"
            + "\"country\":{\"countryName\":\"GeneratedFindingCountryName\"},\"city\":{\"cityName\":\"GeneratedFindingCityName\"},"
            + "\"geoLocation\":{\"lat\":0,\"lon\":0}},\"affectedResources\":{}}},\"resourceRole\":\"TARGET\","
            + "\"additionalInfo\":{\"recentApiCalls\":[{\"api\":\"GeneratedFindingAPIName1\",\"count\":2},{\"api\":\"GeneratedFindingAPIName2\","
            + "\"count\":2}],\"sample\":true},\"eventFirstSeen\":\"2019-06-09T19:10:08.222Z\",\"eventLastSeen\":\"2019-06-09T19:10:23.301Z\","
            + "\"archived\":false,\"count\":2},\"severity\":5,\"createdAt\":\"2019-06-09T19:10:08.222Z\",\"updatedAt\":\"2019-06-09T19:10:23.301Z\","
            + "\"title\":\"Unusual user permission reconnaissance activity by GeneratedFindingUserName.\","
            + "\"description\":\"APIs commonly used to discover the users, groups, policies and permissions in an account,"
            + " was invoked by IAM principal GeneratedFindingUserName under unusual circumstances. "
            + "Such activity is not typically seen from this principal.\"}}";

    Parser p = getTestParser();
    assertNotNull(p);

    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GUARDDUTY, e.getPayloadType());

    GuardDuty gde = e.getPayload();
    assertNotNull(gde);

    Finding gdf = gde.getFinding();
    assertNotNull(gdf);

    assertEquals("2.0", gdf.getSchemaVersion());
    assertEquals("123456789012", gdf.getAccountId());
    assertEquals("us-west-2", gdf.getRegion());
    assertEquals("aws", gdf.getPartition());
    assertEquals("591f8d2ed2edaf6a96ad486b59ed8428", gdf.getId());
    assertEquals(
        "arn:aws:guardduty:us-west-2:123456789012:detector/cab59ed1d9760dbaa8930337156d4547/finding/56b59ed2edaf6a84291f8d2ed96ad488",
        gdf.getArn());
    assertEquals("Recon:IAMUser/UserPermissions", gdf.getType());
    assertEquals(5.0, gdf.getSeverity(), 0.0);
    assertEquals("2019-06-09T19:10:08.222Z", gdf.getCreatedAt());
    assertEquals("2019-06-09T19:10:23.301Z", gdf.getUpdatedAt());
    assertEquals(
        "Unusual user permission reconnaissance activity by GeneratedFindingUserName.",
        gdf.getTitle());
    assertEquals(
        "APIs commonly used to discover the users, groups, policies and permissions in an account, was invoked by IAM principal GeneratedFindingUserName under unusual circumstances. Such activity is not typically seen from this principal.",
        gdf.getDescription());
  }

  @Test
  public void testParseGcpAudit() throws Exception {
    String buf =
        "{\"protoPayload\":{\"@type\":\"type.googleapis.com/google.cloud.audit.AuditLog\","
            + "\"status\":{},\"authenticationInfo\":{\"principalEmail\":\"laforge@mozilla.com\"},"
            + "\"requestMetadata\":{\"callerIp\":\"216.160.83.56\",\"callerSuppliedUserAgent\":\""
            + "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:65.0) Gecko/20100101 Firefox/65.0\""
            + ",\"requestAttributes\":{},\"destinationAttributes\":{}},\"serviceName\":\"cloudresou"
            + "rcemanager.googleapis.com\",\"methodName\":\"SetIamPolicy\",\"authorizationInfo\":[{"
            + "\"resource\":\"projects/test\",\"permission\":\"resourcemanager.projects.setIamPolic"
            + "y\",\"granted\":true,\"resourceAttributes\":{}}],\"resourceName\":\"projects/test\","
            + "\"serviceData\":{\"@type\":\"type.googleapis.com/google.iam.v1.logging.AuditData\","
            + "\"policyDelta\":{\"auditConfigDeltas\":[{\"action\":\"ADD\",\"service\":\"iam.googl"
            + "eapis.com\",\"logType\":\"ADMIN_READ\"},{\"action\":\"ADD\",\"service\":\"iam.googl"
            + "eapis.com\",\"logType\":\"DATA_READ\"},{\"action\":\"ADD\",\"service\":\"iam.google"
            + "apis.com\",\"logType\":\"DATA_WRITE\"}]}},\"request\":{\"@type\":\"type.googleapis."
            + "com/google.iam.v1.SetIamPolicyRequest\",\"policy\":{\"etag\":\"AAAAAAAAAAAA\",\"aud"
            + "itConfigs\":[{\"service\":\"iam.googleapis.com\",\"auditLogConfigs\":[{\"logType\":"
            + "\"ADMIN_READ\"},{\"logType\":\"DATA_READ\"},{\"logType\":\"DATA_WRITE\"}]}]},\"upda"
            + "teMask\":\"\",\"resource\":\"test\"},\"response\":{\"@type\":\"type.googleapis.com/"
            + "google.iam.v1.Policy\",\"etag\":\"AAAAAAAAAAAA\",\"auditConfigs\":[{\"service\":\"i"
            + "am.googleapis.com\",\"auditLogConfigs\":[{\"logType\":\"ADMIN_READ\"},{\"logType\":"
            + "\"DATA_READ\"},{\"logType\":\"DATA_WRITE\"}]}],\"bindings\":[{\"members\":[\"servic"
            + "eAccount:test@test.iam.gserviceaccount.com\"],\"role\":\"roles/bigquery.admin\"}]}}"
            + ",\"insertId\":\"AAAAAAAAAAAA\",\"resource\":{\"type\":\"project\",\"labels\":{\"pro"
            + "ject_id\":\"test\"}},\"timestamp\":\"2019-01-03T20:52:04.782Z\",\"severity\":\"NOTI"
            + "CE\",\"logName\":\"projects/test/logs/cloudaudit.googleapis.com%2Factivity\",\"rece"
            + "iveTimestamp\":\"2019-01-03T20:52:05.807173206Z\"}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GCPAUDIT, e.getPayloadType());
    assertEquals("2019-01-03T20:52:04.782Z", e.getTimestamp().toString());
    GcpAudit d = e.getPayload();
    assertNotNull(d);
    assertEquals("laforge@mozilla.com", d.getPrincipalEmail());
    assertEquals("projects/test", d.getResource());
    assertEquals("216.160.83.56", d.getCallerIp());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH_SESSION));
    assertEquals("laforge@mozilla.com", n.getSubjectUser());
    assertEquals("projects/test", n.getObject());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
    assertEquals(47.25, n.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, n.getSourceAddressLongitude(), 0.5);
  }

  @Test
  public void testParseNginxStackdriverVariant1() throws Exception {
    String buf =
        "{\"insertId\":\"XXXXXXXXXXXXX\",\"jsonPayload\":{\"x_forwarded_proto\":\"https\",\"remote_"
            + "addr\":\"216.160.83.56\",\"user_agent\":\"Mozilla\",\"referrer\":\"https://mozilla.org/\",\""
            + "request\":\"POST /test/endpoint?t=t HTTP/1.1\",\"remote_user\":\"\",\"request_time\":0.005,\"by"
            + "tes_sent\":175,\"trace\":\"0000000000000000000000000000000000000000000000000000\",\"status"
            + "\":\"200\",\"x_forwarded_for\":\"216.160.83.56, 127.0.0.1\"},\"resource\":{\"type\":\"k8s_"
            + "container\",\"labels\":{\"project_id\":\"test\",\"pod_name\":\"test\",\"cluster_name\":\"t"
            + "est\",\"container_name\":\"nginx\",\"namespace_name\":\"prod-test\",\"location\":\"us-west"
            + "1\"}},\"timestamp\":\"2019-01-27T04:09:37Z\",\"severity\":\"INFO\",\"logName\":\"projects/"
            + "test/logs/stdout\",\"receiveTimestamp\":\"2019-01-27T04:09:43.557934256Z\",\"metadata\":{\""
            + "systemLabels\":{\"provider_zone\":\"us-west1-c\",\"top_level_controller_name\":\"test\",\"n"
            + "ode_name\":\"gke-test\",\"container_image\":\"gcr.io/test\",\"provider_resource_type\":\"gc"
            + "e_instance\",\"top_level_controller_type\":\"Deployment\",\"name\":\"nginx\",\"container_im"
            + "age_id\":\"docker-pullable://test\",\"service_name\":[\"test\"],\"provider_instance_id\":\""
            + "0000000000000000000\"},\"userLabels\":{\"app.kubernetes.io/managed-by\":\"test\",\"app.kube"
            + "rnetes.io/version\":\"1.0.0\",\"app.kubernetes.io/component\":\"app\",\"app.kubernetes.io/i"
            + "nstance\":\"prod\",\"pod-template-hash\":\"000000000\",\"app.kubernetes.io/part-of\":\"test"
            + "\",\"fullname\":\"test\",\"jenkins-build-id\":\"0\",\"app.kubernetes.io/name\":\"test\"}}}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.NGINX, e.getPayloadType());
    Nginx d = e.getPayload();
    assertNotNull(d);
    assertEquals(200, (int) d.getStatus());
    assertEquals("https://mozilla.org/", d.getReferrer());
    assertEquals("POST /test/endpoint?t=t HTTP/1.1", d.getRequest());
    assertEquals("POST", d.getRequestMethod());
    assertEquals("/test/endpoint?t=t", d.getRequestUrl());
    assertEquals("/test/endpoint", d.getRequestPath());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("POST", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals("/test/endpoint?t=t", n.getRequestUrl());
    assertEquals("/test/endpoint", n.getUrlRequestPath());
    assertEquals("216.160.83.56", n.getSourceAddress());
  }

  @Test
  public void testParseNginxStackdriverVariant2() throws Exception {
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
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.NGINX, e.getPayloadType());
    Nginx d = e.getPayload();
    assertNotNull(d);
    assertEquals(200, (int) d.getStatus());
    assertEquals("https://bugzilla.mozilla.org/show_bug.cgi?id=0", d.getReferrer());
    assertEquals("POST /rest/bug_user_last_visit/000000?t=t HTTP/1.1", d.getRequest());
    assertEquals("POST", d.getRequestMethod());
    assertEquals("/rest/bug_user_last_visit/000000?t=t", d.getRequestUrl());
    assertEquals("/rest/bug_user_last_visit/000000", d.getRequestPath());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("POST", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals("/rest/bug_user_last_visit/000000?t=t", n.getRequestUrl());
    assertEquals("/rest/bug_user_last_visit/000000", n.getUrlRequestPath());
    assertEquals("216.160.83.56", n.getSourceAddress());
  }

  @Test
  public void testParseNginxStackdriverVariant2MultiRemote() throws Exception {
    // Test cases where the remote_ip field contains multiple addresses, e.g., XFF
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAA\",\"jsonPayload\":{\"agent\":\"Mozilla/5.0\",\"bytes_sent\""
            + ":\"97\",\"cache_status\":\"-\",\"code\":\"200\",\"gzip_ratio\":\"0.68\",\"referrer\":\"h"
            + "ttps://bugzilla.mozilla.org/ping?id=0\",\"remote_ip\":\"10.0.0.1, 216.160.83.56\",\"req_ti"
            + "me\":\"0.136\",\"request\":\"POST /rest/bug_user_last_visit/000000?t=t HTTP/1.1\",\"res_"
            + "time\":\"0.136\"},\"labels\":{\"application\":\"bugzilla\",\"ec2.amazonaws.com/resource_"
            + "name\":\"ip1.us-west-2.compute.internal\",\"env\":\"test\",\"stack\":\"app\",\"type\":\""
            + "app\"},\"logName\":\"projects/test/logs/test\",\"receiveTimestamp\":\"2019-01-31T17:49:5"
            + "9.539710898Z\",\"resource\":{\"labels\":{\"aws_account\":\"000000000000\",\"instance_id\""
            + ":\"i-00000000000000000\",\"project_id\":\"test\",\"region\":\"aws:us-west-2c\"},\"type\":"
            + "\"aws_ec2_instance\"},\"timestamp\":\"2019-01-31T17:49:57Z\"}";
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.NGINX, e.getPayloadType());
    Nginx d = e.getPayload();
    assertNotNull(d);
    assertEquals(200, (int) d.getStatus());
    assertEquals("https://bugzilla.mozilla.org/ping?id=0", d.getReferrer());
    assertEquals("POST /rest/bug_user_last_visit/000000?t=t HTTP/1.1", d.getRequest());
    assertEquals("POST", d.getRequestMethod());
    assertEquals("/rest/bug_user_last_visit/000000?t=t", d.getRequestUrl());
    assertEquals("/rest/bug_user_last_visit/000000", d.getRequestPath());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("POST", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals("/rest/bug_user_last_visit/000000?t=t", n.getRequestUrl());
    assertEquals("/rest/bug_user_last_visit/000000", n.getUrlRequestPath());
    assertEquals("216.160.83.56", n.getSourceAddress());
  }

  @Test
  public void testParseETDFindingStackdriver() throws Exception {
    String buf =
        "{ \"insertId\": \"-7744mva3\","
            + "  \"logName\": \"projects/eap-testing-project/logs/threatdetection.googleapis.com%2Fdetection\","
            + "  \"receiveTimestamp\": \"2019-01-29T20:54:12.014780631Z\","
            + "  \"severity\": \"CRITICAL\","
            + "  \"timestamp\": \"2019-01-29T20:54:10.606Z\","
            + "  \"resource\": {"
            + "    \"labels\": {"
            + "      \"detector_name\": \"bad_domain\","
            + "      \"project_id\": \"eap-testing-project\""
            + "    },"
            + "    \"type\": \"threat_detector\""
            + "  },"
            + "  \"jsonPayload\": {"
            + "    \"detectionCategory\": {"
            + "      \"indicator\": \"domain\","
            + "      \"ruleName\": \"bad_domain\","
            + "      \"technique\": \"Malware\""
            + "    },"
            + "    \"detectionPriority\": \"HIGH\","
            + "    \"eventTime\": \"2019-01-29T20:54:10.606Z\","
            + "    \"evidence\": ["
            + "      {"
            + "        \"sourceLogId\": {"
            + "          \"insertId\": \"abm9qg1umid1u\","
            + "          \"timestamp\": \"2019-01-29T20:54:09.379016055Z\""
            + "        }"
            + "      }"
            + "    ],"
            + "    \"properties\": {"
            + "      \"domain\": ["
            + "        \"3322.org\""
            + "      ],"
            + "      \"location\": \"us-east1-b\","
            + "      \"project_id\": \"eap-testing-project\","
            + "      \"subnetwork_id\": \"6331192180620506838\","
            + "      \"subnetwork_name\": \"default\""
            + "    },"
            + "    \"sourceId\": {"
            + "      \"customerOrganizationNumber\": \"556172058706\","
            + "      \"projectNumber\": \"883576422677\""
            + "    }"
            + "  }"
            + "}";

    ParserCfg cfg = new ParserCfg();
    assertNotNull(cfg);

    Parser p = new Parser(cfg);
    assertNotNull(p);

    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.ETD, e.getPayloadType());

    ETDBeta etdParser = e.getPayload();
    assertNotNull(etdParser);

    EventThreatDetectionFinding etdf = etdParser.getFinding();
    assertNotNull(etdf);

    assertEquals("HIGH", etdf.getDetectionPriority());
    assertEquals("2019-01-29T20:54:10.606Z", etdf.getEventTime());

    assertNotNull(etdf.getDetectionCategory());
    assertEquals("domain", etdf.getDetectionCategory().getIndicator());
    assertEquals("bad_domain", etdf.getDetectionCategory().getRuleName());
    assertEquals("Malware", etdf.getDetectionCategory().getTechnique());

    assertNotNull(etdf.getProperties());
    assertEquals("us-east1-b", etdf.getProperties().getLocation());
    assertEquals("eap-testing-project", etdf.getProperties().getProject_id());
    assertEquals("6331192180620506838", etdf.getProperties().getSubnetwork_id());
    assertEquals("default", etdf.getProperties().getSubnetwork_name());
    assertEquals(1, etdf.getProperties().getDomain().size());
    assertEquals("3322.org", etdf.getProperties().getDomain().get(0));

    assertNotNull(etdf.getEvidence());
    assertEquals(1, etdf.getEvidence().size());
    assertNotNull(etdf.getEvidence().get(0));
    assertNotNull(etdf.getEvidence().get(0).getSourceLogId());
    assertEquals("abm9qg1umid1u", etdf.getEvidence().get(0).getSourceLogId().getInsertId());
    assertEquals(
        "2019-01-29T20:54:09.379016055Z",
        etdf.getEvidence().get(0).getSourceLogId().getTimestamp());

    assertNotNull(etdf.getSourceId());
    assertEquals("556172058706", etdf.getSourceId().getCustomerOrganizationNumber());
    assertEquals("883576422677", etdf.getSourceId().getProjectNumber());
  }

  @Test
  public void testParseETDFinding() throws Exception {
    String buf =
        "  {  \"detectionCategory\": {"
            + "      \"indicator\": \"domain\","
            + "      \"ruleName\": \"bad_domain\","
            + "      \"technique\": \"Malware\""
            + "    },"
            + "    \"detectionPriority\": \"HIGH\","
            + "    \"eventTime\": \"2019-01-29T20:54:10.606Z\","
            + "    \"evidence\": ["
            + "        {"
            + "        \"sourceLogId\": {"
            + "          \"insertId\": \"abm9qg1umid1u\","
            + "          \"timestamp\": \"2019-01-29T20:54:09.379016055Z\""
            + "        }"
            + "      }"
            + "    ],"
            + "    \"properties\": {"
            + "      \"domain\": ["
            + "        \"3322.org\""
            + "      ],"
            + "      \"location\": \"us-east1-b\","
            + "      \"project_id\": \"eap-testing-project\","
            + "      \"subnetwork_id\": \"6331192180620506838\","
            + "      \"subnetwork_name\": \"default\""
            + "    },"
            + "    \"sourceId\": {"
            + "      \"customerOrganizationNumber\": \"556172058706\","
            + "      \"projectNumber\": \"883576422677\""
            + "    }"
            + "}";

    ParserCfg cfg = new ParserCfg();
    assertNotNull(cfg);

    Parser p = new Parser(cfg);
    assertNotNull(p);

    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.ETD, e.getPayloadType());

    ETDBeta etdParser = e.getPayload();
    assertNotNull(etdParser);

    EventThreatDetectionFinding etdf = etdParser.getFinding();
    assertNotNull(etdf);

    assertEquals("HIGH", etdf.getDetectionPriority());
    assertEquals("2019-01-29T20:54:10.606Z", etdf.getEventTime());

    assertNotNull(etdf.getDetectionCategory());
    assertEquals("domain", etdf.getDetectionCategory().getIndicator());
    assertEquals("bad_domain", etdf.getDetectionCategory().getRuleName());
    assertEquals("Malware", etdf.getDetectionCategory().getTechnique());

    assertNotNull(etdf.getProperties());
    assertEquals("us-east1-b", etdf.getProperties().getLocation());
    assertEquals("eap-testing-project", etdf.getProperties().getProject_id());
    assertEquals("6331192180620506838", etdf.getProperties().getSubnetwork_id());
    assertEquals("default", etdf.getProperties().getSubnetwork_name());
    assertEquals(1, etdf.getProperties().getDomain().size());
    assertEquals("3322.org", etdf.getProperties().getDomain().get(0));

    assertNotNull(etdf.getEvidence());
    assertEquals(1, etdf.getEvidence().size());
    assertNotNull(etdf.getEvidence().get(0));
    assertNotNull(etdf.getEvidence().get(0).getSourceLogId());
    assertEquals("abm9qg1umid1u", etdf.getEvidence().get(0).getSourceLogId().getInsertId());
    assertEquals(
        "2019-01-29T20:54:09.379016055Z",
        etdf.getEvidence().get(0).getSourceLogId().getTimestamp());

    assertNotNull(etdf.getSourceId());
    assertEquals("556172058706", etdf.getSourceId().getCustomerOrganizationNumber());
    assertEquals("883576422677", etdf.getSourceId().getProjectNumber());
  }

  @Test
  public void testParseApacheCombined() throws Exception {
    String buf =
        "\"216.160.83.56\" - - [19/Mar/2019:14:52:39 -0500] \"GET /assets/scripts/main.js?t=t HTTP/1.1\" 200"
            + " 3697 \"https://mozilla.org/item/10\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:"
            + "65.0) Gecko/20100101 Firefox/65.0\"";
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.APACHE_COMBINED, e.getPayloadType());

    ApacheCombined d = e.getPayload();
    assertNotNull(d);
    assertNull(d.getRemoteUser());
    assertEquals(200, (int) d.getStatus());
    assertEquals("https://mozilla.org/item/10", d.getReferrer());
    assertEquals("GET /assets/scripts/main.js?t=t HTTP/1.1", d.getRequest());
    assertEquals("GET", d.getRequestMethod());
    assertEquals("/assets/scripts/main.js?t=t", d.getRequestUrl());
    assertEquals(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:65.0) Gecko/20100101 Firefox/65.0",
        d.getUserAgent());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("GET", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals("/assets/scripts/main.js?t=t", n.getRequestUrl());
    assertEquals("/assets/scripts/main.js", n.getUrlRequestPath());
    assertEquals("216.160.83.56", n.getSourceAddress());
  }

  @Test
  public void testParseApacheCombinedXffUser() throws Exception {
    String buf =
        "\"127.0.0.1, 10.0.0.1, 216.160.83.56\" - riker [19/Mar/2019:14:52:39 -0500] "
            + "\"GET /assets/scripts/main.js?t=t HTTP/1.1\" 200"
            + " 3697 \"https://mozilla.org/item/10\" \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:"
            + "65.0) Gecko/20100101 Firefox/65.0\"";
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.APACHE_COMBINED, e.getPayloadType());

    ApacheCombined d = e.getPayload();
    assertNotNull(d);
    assertEquals("riker", d.getRemoteUser());
    assertEquals(200, (int) d.getStatus());
    assertEquals("https://mozilla.org/item/10", d.getReferrer());
    assertEquals("GET /assets/scripts/main.js?t=t HTTP/1.1", d.getRequest());
    assertEquals("GET", d.getRequestMethod());
    assertEquals("/assets/scripts/main.js?t=t", d.getRequestUrl());
    assertEquals(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:65.0) Gecko/20100101 Firefox/65.0",
        d.getUserAgent());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("GET", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals("/assets/scripts/main.js?t=t", n.getRequestUrl());
    assertEquals("/assets/scripts/main.js", n.getUrlRequestPath());
    assertEquals("216.160.83.56", n.getSourceAddress());
  }

  @Test
  public void testParseFxaAuth() throws Exception {
    String buf =
        "{\"insertId\":\"AAAAAAAAAAAAA\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fields"
            + "\":{\"agent\":\"Mozilla/5.0\",\"email\":\"spock@mozilla.com\",\"errno\":103,\"ke"
            + "ys\":true,\"lang\":\"en-US,en;q=0.5\",\"method\":\"post\",\"op\":\"request.summa"
            + "ry\",\"path\":\"/v1/account/login\",\"reason\":\"signin\",\"remoteAddressChain\""
            + ":\"[\\\"0.0.0.0\\\",\\\"216.160.83.56\\\",\\\"127.0.0.1\\\"]\",\"service\":\"sync\",\""
            + "status\":400,\"t\":191,\"uid\":\"00\"},\"Logger\":\"fxa-auth-server\",\"Pid\":1,"
            + "\"Severity\":6,\"Timestamp\":1550249793121000000,\"Type\":\"request.summary\"},\""
            + "labels\":{\"application\":\"fxa\",\"compute.googleapis.com/resource_name\":\"fxa"
            + "\",\"env\":\"prod\",\"stack\":\"default\",\"type\":\"auth_server\"},\"logName\":"
            + "\"projects/test/logs/docker.fxa-auth\",\"receiveTimestamp\":\"2019-02-15T16:56:3"
            + "7.313724705Z\",\"resource\":{\"labels\":{\"instance_id\":\"i-08\",\"project_id\""
            + ":\"test\",\"zone\":\"us-west-2c\"},\"type\":\"gce_instance\"},\"timestamp\":\"20"
            + "19-02-15T16:56:33.121592986Z\"}";
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(TEST_GEOIP_DBPATH);
    ArrayList<String> xffa = new ArrayList<>();
    xffa.add("127.0.0.1/32");
    cfg.setXffAddressSelector(xffa);
    Parser p = new Parser(cfg);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.FXAAUTH, e.getPayloadType());
    FxaAuth d = e.getPayload();
    assertNotNull(d);

    com.mozilla.secops.parser.models.fxaauth.FxaAuth f = d.getFxaAuthData();
    assertEquals("sync", f.getService());
    assertEquals("Mozilla/5.0", f.getAgent());
    assertEquals("/v1/account/login", f.getPath());
    assertEquals(400, (int) f.getStatus());
    assertEquals(
        com.mozilla.secops.parser.models.fxaauth.FxaAuth.Errno.INCORRECT_PASSWORD, f.getErrno());
    assertEquals(FxaAuth.EventSummary.LOGIN_FAILURE, d.getEventSummary());
    assertEquals("216.160.83.56", d.getSourceAddress());
    assertEquals("Milton", d.getSourceAddressCity());
    assertEquals("US", d.getSourceAddressCountry());
    assertEquals(47.25, d.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, d.getSourceAddressLongitude(), 0.5);
    assertEquals("2019-02-15T16:56:33.121Z", e.getTimestamp().toString());

    buf =
        "{\"insertId\":\"xxxxxxxxxxxxxx\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fields\""
            + ":{\"agent\":\"Mozilla/5.0 (Windows NT 6.1; rv:65.0) Gecko/20100101 Firefox/65.0\","
            + "\"email\":\"riker@mozilla.com\",\"errno\":0,\"keys\":true,\"lang\":\"pt-BR,pt;q=0."
            + "8,en-US;q=0.5,en;q=0.3\",\"method\":\"post\",\"op\":\"request.summary\",\"path\":\""
            + "/v1/account/login\",\"reason\":\"signin\",\"remoteAddressChain\":\"[\\\"10.0.0.1\\\""
            + ",\\\"127.0.0.1\\\"]\",\"service\":\"sync\",\"status\":200,\"t\":386,\"uid\":\"000000"
            + "00000000000000000000000000\"},\"Logger\":\"fxa-auth-server\",\"Pid\":1,\"Severity\":"
            + "6,\"Timestamp\":0,\"Type\":\"request.summary\"},\"labels\":{\"application\":\"fxa\","
            + "\"compute.googleapis.com/resource_name\":\"fxa\",\"env\":\"prod\",\"stack\":\"defaul"
            + "t\",\"type\":\"auth_server\"},\"logName\":\"projects/fxa/logs/docker.fxa-auth\",\"re"
            + "ceiveTimestamp\":\"2019-02-15T16:56:35.857842822Z\",\"resource\":{\"labels\":{\"inst"
            + "ance_id\":\"i\",\"project_id\":\"fxa\",\"zone\":\"us-west-2c\"},\"type\":\"gce_insta"
            + "nce\"},\"timestamp\":\"2019-02-15T16:56:31.277548851Z\"}";
    e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.FXAAUTH, e.getPayloadType());
    d = e.getPayload();
    assertNotNull(d);

    f = d.getFxaAuthData();
    assertEquals("sync", f.getService());
    assertEquals("Mozilla/5.0 (Windows NT 6.1; rv:65.0) Gecko/20100101 Firefox/65.0", f.getAgent());
    assertEquals("/v1/account/login", f.getPath());
    assertEquals("00000000000000000000000000000000", f.getUid());
    assertEquals(200, (int) f.getStatus());
    assertEquals("10.0.0.1", d.getSourceAddress());
    assertEquals(FxaAuth.EventSummary.LOGIN_SUCCESS, d.getEventSummary());

    // FxA will log "00" as a UID if no UID is present, verify this is correctly returned as
    // null from an event like this.
    buf =
        "{\"insertId\":\"xxxxxxxxxxxxxx\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fields\""
            + ":{\"agent\":\"Mozilla/5.0 (Windows NT 6.1; rv:65.0) Gecko/20100101 Firefox/65.0\","
            + "\"email\":\"riker@mozilla.com\",\"errno\":0,\"keys\":true,\"lang\":\"pt-BR,pt;q=0."
            + "8,en-US;q=0.5,en;q=0.3\",\"method\":\"post\",\"op\":\"request.summary\",\"path\":\""
            + "/v1/account/login\",\"reason\":\"signin\",\"remoteAddressChain\":\"[\\\"10.0.0.1\\\""
            + ",\\\"127.0.0.1\\\"]\",\"service\":\"sync\",\"status\":200,\"t\":386,\"uid\":\"00"
            + "\"},\"Logger\":\"fxa-auth-server\",\"Pid\":1,\"Severity\":"
            + "6,\"Timestamp\":0,\"Type\":\"request.summary\"},\"labels\":{\"application\":\"fxa\","
            + "\"compute.googleapis.com/resource_name\":\"fxa\",\"env\":\"prod\",\"stack\":\"defaul"
            + "t\",\"type\":\"auth_server\"},\"logName\":\"projects/fxa/logs/docker.fxa-auth\",\"re"
            + "ceiveTimestamp\":\"2019-02-15T16:56:35.857842822Z\",\"resource\":{\"labels\":{\"inst"
            + "ance_id\":\"i\",\"project_id\":\"fxa\",\"zone\":\"us-west-2c\"},\"type\":\"gce_insta"
            + "nce\"},\"timestamp\":\"2019-02-15T16:56:31.277548851Z\"}";
    e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.FXAAUTH, e.getPayloadType());
    d = e.getPayload();
    assertNotNull(d);
    f = d.getFxaAuthData();
    assertNull(f.getUid());

    buf =
        "{\"insertId\":\"00000000000000\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fiel"
            + "ds\":{\"agent\":\"Mozilla/5.0 (Android 7.0; Mobile; rv:65.0) Gecko/65.0 Firefox"
            + "/65.0\",\"email\":\"riker@mozilla.com\",\"errno\":0,\"lang\":\"en-GB,en;q=0.5\""
            + ",\"method\":\"post\",\"op\":\"request.summary\",\"path\":\"/v1/password/forgot/"
            + "send_code\",\"remoteAddressChain\":\"[\\\"10.0.0.1\\\",\\\"127.0.0.1\\\"]\",\"s"
            + "ervice\":\"sync\",\"status\":200,\"t\":210,\"uid\":\"00\"},\"Logger\":\"fxa-aut"
            + "h-server\",\"Pid\":1,\"Severity\":6,\"Timestamp\":0,\"Type\":\"request.summary\""
            + "},\"labels\":{\"application\":\"fxa\",\"compute.googleapis.com/resource_name\":\"fxa\""
            + ",\"env\":\"prod\",\"stack\":\"default\",\"type\":\"auth_server\"},\"logName\":\"projec"
            + "ts/fxa\",\"receiveTimestamp\":\"2019-02-15T16:56:49.052372026Z\",\"resource\":{\"label"
            + "s\":{\"instance_id\":\"i0\",\"project_id\":\"fxa\",\"zone\":\"us-west-2b\"},\"type\":"
            + "\"gce_instance\"},\"timestamp\":\"2019-02-15T16:56:45.751112714Z\"}";
    e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.FXAAUTH, e.getPayloadType());
    d = e.getPayload();
    assertNotNull(d);
    f = d.getFxaAuthData();
    assertEquals(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_SUCCESS, d.getEventSummary());

    buf =
        "{\"insertId\":\"00000000000000\",\"jsonPayload\":{\"EnvVersion\":\"2.0\",\"Fiel"
            + "ds\":{\"agent\":\"Mozilla/5.0 (Android 7.0; Mobile; rv:65.0) Gecko/65.0 Firefox"
            + "/65.0\",\"email\":\"riker@mozilla.com\",\"errno\":102,\"lang\":\"en-GB,en;q=0.5\""
            + ",\"method\":\"post\",\"op\":\"request.summary\",\"path\":\"/v1/password/forgot/"
            + "send_code\",\"remoteAddressChain\":\"[\\\"10.0.0.1\\\",\\\"127.0.0.1\\\"]\",\"s"
            + "ervice\":\"sync\",\"status\":400,\"t\":210,\"uid\":\"00\"},\"Logger\":\"fxa-aut"
            + "h-server\",\"Pid\":1,\"Severity\":6,\"Timestamp\":0,\"Type\":\"request.summary\""
            + "},\"labels\":{\"application\":\"fxa\",\"compute.googleapis.com/resource_name\":\"fxa\""
            + ",\"env\":\"prod\",\"stack\":\"default\",\"type\":\"auth_server\"},\"logName\":\"projec"
            + "ts/fxa\",\"receiveTimestamp\":\"2019-02-15T16:56:49.052372026Z\",\"resource\":{\"label"
            + "s\":{\"instance_id\":\"i0\",\"project_id\":\"fxa\",\"zone\":\"us-west-2b\"},\"type\":"
            + "\"gce_instance\"},\"timestamp\":\"2019-02-15T16:56:45.751112714Z\"}";
    e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.FXAAUTH, e.getPayloadType());
    d = e.getPayload();
    assertNotNull(d);
    f = d.getFxaAuthData();
    assertEquals(FxaAuth.EventSummary.PASSWORD_FORGOT_SEND_CODE_FAILURE, d.getEventSummary());
  }

  @Test
  public void testGeoIp() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    CityResponse resp = p.geoIp("216.160.83.56");
    assertNotNull(resp);
    assertEquals("US", resp.getCountry().getIsoCode());
    assertEquals("Milton", resp.getCity().getName());
  }

  @Test
  public void testParseJsonSerializeDeserializeRaw() throws Exception {
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse("test");
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw r = e.getPayload();
    assertNotNull(r);
    assertEquals("test", r.getRaw());

    Event e2 = Event.fromJSON(e.toJSON());
    assertNotNull(e2);
    Raw r2 = e2.getPayload();
    assertNotNull(r2);

    assertEquals(e.getEventId(), e2.getEventId());
    assertEquals(e.getTimestamp(), e2.getTimestamp());
    assertEquals(e.getPayloadType(), e2.getPayloadType());
    assertEquals(r.getRaw(), r2.getRaw());
  }

  @Test
  public void testParseJsonSerializeDeserializeMozlogDuopull() throws Exception {
    String buf =
        "{\"EnvVersion\": \"2.0\", \"Severity\": 6, \"Fields\": "
            + "{\"event_description_valid_secs\": 3600, \"event_description_count\": 1, "
            + "\"event_description_user_id\": \"ZZZZZZZZZZZZZZZZZZZZ\", \"event_object\": \"worf\", "
            + "\"event_timestamp\": 1530282703, \"event_username\": \"First Last\", "
            + "\"event_description_bypass_code_ids\": [\"XXXXXXXXXXXXXXXXXXXX\"], "
            + "\"event_description_bypass\": \"\", \"path\": \"/admin/v1/logs/administrator\", "
            + "\"msg\": \"duopull event\", \"event_action\": \"bypass_create\", "
            + "\"event_description_auto_generated\": true, \"event_description_remaining_uses\": 1}, "
            + "\"Hostname\": \"test\", \"Pid\": 62312, \"Time\": \"2018-07-04T15:49:46Z\", "
            + "\"Logger\": \"duopull\", \"Type\": \"app.log\", \"Timestamp\": 1530719386349480000}";
    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    Mozlog m = e.getMozlog();
    assertNotNull(m);
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());

    Event e2 = Event.fromJSON(e.toJSON());
    assertNotNull(e2);
    Mozlog m2 = e2.getMozlog();
    assertNotNull(m2);
    Duopull d2 = e2.getPayload();
    assertNotNull(d2);
    com.mozilla.secops.parser.models.duopull.Duopull data2 = d2.getDuopullData();
    assertNotNull(data2);
    assertEquals(e.getEventId(), e2.getEventId());
    assertNotEquals(e.getTimestamp(), e2.getTimestamp());
    assertEquals(e.getPayloadType(), e2.getPayloadType());

    assertEquals(data.getEventTimestamp(), data2.getEventTimestamp());
    assertEquals(data.getEventAction(), data2.getEventAction());

    assertEquals(m.getHostname(), m2.getHostname());
    assertEquals(m.getLogger(), m2.getLogger());
  }

  @Test
  public void testParseCfgTick() throws Exception {
    String buf =
        "{\"configuration_tick\": true, \"string\": \"test\", \"integer\": 100, \"boolean\": true,"
            + "\"array_string\": [\"one\", \"two\"], \"array_int\": [1, 2]}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CFGTICK, e.getPayloadType());
    CfgTick c = e.getPayload();
    assertNotNull(c);
    Map<String, String> configMap = c.getConfigurationMap();
    assertNotNull(configMap);
    assertEquals("true", configMap.get("boolean"));
    assertEquals("100", configMap.get("integer"));
    assertEquals("test", configMap.get("string"));
    assertEquals("one, two", configMap.get("array_string"));
    assertEquals("1, 2", configMap.get("array_int"));
  }

  @Test
  public void testParseSyslogTs() throws Exception {
    String[] datelist = {
      "Feb  8 20:23:32", "Sep 18 20:23:32", "Sep 18 15:23:32", "Dec 31 15:23:32",
    };
    Long[] inMs = {1549657412000L, 1568838212000L, 1568820212000L, 1577805812000L};

    for (int i = 0; i < datelist.length; i++) {
      Long d = Parser.parseSyslogTs(datelist[i]).withYear(2019).getMillis();

      assertEquals(inMs[i], d);
    }
    assertNull(Parser.parseSyslogTs("not-a-date"));
  }

  @Test
  public void testParseAndCorrectSyslogTs() throws Exception {
    Event e = new Event();
    e.setTimestamp(Parser.parseISO8601("2018-09-19T18:55:12.469Z"));

    String[] datelist = {"Feb  8 20:23:32", "Sep 18 20:23:32"};
    for (String t : datelist) {
      DateTime et = Parser.parseAndCorrectSyslogTs(t, e);
      assertEquals(2018, et.year().get());
    }
    assertNull(Parser.parseAndCorrectSyslogTs("not-a-date", e));
  }

  @Test
  public void testAuth0RawAuth() throws Exception {
    String buf =
        "{\"_id\": \"5734829321d6731f1b94e07a\",\"log_id\": null,\"date\": "
            + "\"2019-06-29T17:44:08.135Z\",\"type\": \"s\",\"client_id\": \"XXXXXXXXXXXX\","
            + "\"client_name\": \"www.enterprise.com\",\"ip\": \"10.0.0.167\",\"location_info\":"
            + "null,\"details\": {\"completedAt\": 1561830248134,\"elapsedTime\": 2914,"
            + "\"initiatedAt\": 1561830245220,\"prompts\": [{\"completedAt\": 1561830247694,"
            + "\"connection\": \"Enterprise-LDAP\",\"connection_id\": \"con_XXXXXXXXXX\","
            + "\"elapsedTime\": 281,\"identity\": \"Enterprise-LDAP|wriker\",\"initiatedAt\":"
            + "1561830247413,\"name\": \"lock-password-authenticate\",\"session_user\": "
            + "\"XXXXXXXXXXXXXXx\",\"stats\": {\"loginsCount\": 1946740},\"strategy\": \"ad\"},"
            + "{\"completedAt\": 1561830247696,\"elapsedTime\": 2475,\"flow\": \"login\","
            + "\"initiatedAt\": 1561830245221,\"name\": \"login\",\"timers\": {\"rules\": 621},"
            + "\"user_id\": \"ad|Enterprise-LDAP|wriker\",\"user_name\": \"wriker@mozilla.com\"}],"
            + "\"session_id\": \"XXXXXXXXXXXXXXXXXX\",\"stats\": {\"loginsCount\": 740}},"
            + "\"user_id\": \"ad|Enterprise-LDAP|wriker\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    assertEquals("2019-06-29T17:44:08.135Z", e.getTimestamp().toString());
    Auth0 a0 = e.getPayload();
    assertNotNull(a0);
    assertEquals("wriker@mozilla.com", a0.getUsername());
    assertEquals("10.0.0.167", a0.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("wriker@mozilla.com", n.getSubjectUser());
    assertEquals("10.0.0.167", n.getSourceAddress());
    assertEquals("www.enterprise.com", n.getObject());
  }

  @Test
  public void testAuth0StackdriverAuth() throws Exception {
    String buf =
        "{\"insertId\": \"n12d5meka87i\",\"jsonPayload\":{\"_id\":\"5734829321d6731f1b94e07a\","
            + "\"log_id\": null,\"date\": \"2019-06-29T17:44:08.135Z\",\"type\":\"s\",\"client_id\":"
            + "\"XXXXXXXXXXXX\",\"client_name\": \"www.enterprise.com\",\"ip\":\"10.0.0.167\","
            + "\"location_info\": null,\"details\": {\"completedAt\":1561830248134,\"elapsedTime\": "
            + "2914,\"initiatedAt\": 1561830245220,\"prompts\": [{\"completedAt\":1561830247694,"
            + "\"connection\": \"Enterprise-LDAP\",\"connection_id\":\"con_XXXXXXXXXX\",\"elapsedTime\":"
            + "281,\"identity\": \"Enterprise-LDAP|wriker\",\"initiatedAt\":1561830247413,\"name\":"
            + "\"lock-password-authenticate\",\"session_user\": \"XXXXXXXXXXXXXXx\",\"stats\":"
            + "{\"loginsCount\": 1946740},\"strategy\": \"ad\"},{\"completedAt\":1561830247696,\"elapsedTime\":"
            + "2475,\"flow\": \"login\",\"initiatedAt\": 1561830245221,\"name\":\"login\",\"timers\": "
            + "{\"rules\": 621},\"user_id\": \"ad|Enterprise-LDAP|wriker\",\"user_name\": "
            + "\"wriker@mozilla.com\"}],\"session_id\": \"XXXXXXXXXXXXXXXXXX\",\"stats\": "
            + "{\"loginsCount\": 740}},\"user_id\": \"ad|Enterprise-LDAP|wriker\"},"
            + "\"resource\": {\"type\": \"project\",\"labels\": {\"project_id\": "
            + "\"foxsec-pipeline-nonprod\"}},\"timestamp\":\"2019-07-26T17:51:08.907029090Z\","
            + "\"logName\": \"projects/foxsec-pipeline-nonprod/logs/auth0pull\","
            + "\"receiveTimestamp\": \"2019-07-26T17:51:08.949159684Z\"}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    assertEquals("2019-06-29T17:44:08.135Z", e.getTimestamp().toString());
    Auth0 a0 = e.getPayload();
    assertNotNull(a0);
    assertEquals("wriker@mozilla.com", a0.getUsername());
    assertEquals("10.0.0.167", a0.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("wriker@mozilla.com", n.getSubjectUser());
    assertEquals("10.0.0.167", n.getSourceAddress());
    assertEquals("www.enterprise.com", n.getObject());
  }

  @Test
  public void testAuth0Event() throws Exception {
    String buf =
        "{\"client_id\": \"TESTCLIENTID\",\"location_info\": null,"
            + "\"user_id\": \"\",\"log_id\": null,\"client_name\": "
            + "\"enterprise_publisher\",\"_id\": \"11111115d3b354d\","
            + "\"details\": null,\"ip\": \"10.0.0.244\",\"type\": "
            + "\"seccft\",\"date\": \"2019-07-26T17:15:57.235Z\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    assertEquals("2019-07-26T17:15:57.235Z", e.getTimestamp().toString());
    Auth0 a0 = e.getPayload();
    assertNotNull(a0);
    assertNull(a0.getUsername());
    assertEquals("10.0.0.244", a0.getSourceAddress());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertFalse(n.isOfType(Normalized.Type.AUTH));
  }

  @Test
  public void testAuth0EventClientIdArrayAsRaw() throws Exception {
    // This tests handling of a current bug where sometimes client ids are arrays.
    // We want to discard these events for now.
    String buf =
        "{\"client_id\": [\"TESTCLIENTID\", \"ANOTHERID\"],\"location_info\": null,"
            + "\"user_id\": \"\",\"log_id\": null,\"client_name\": "
            + "\"enterprise_publisher\",\"_id\": \"11111115d3b354d\","
            + "\"details\": null,\"ip\": \"10.0.0.244\",\"type\": "
            + "\"seccft\",\"date\": \"2019-07-26T17:15:57.235Z\"}}";

    Parser p = getTestParser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    Raw a0 = e.getPayload();
    assertNotNull(a0);
    Normalized n = e.getNormalized();
    assertFalse(n.isOfType(Normalized.Type.AUTH));
    assertFalse(n.isOfType(Normalized.Type.AUTH_SESSION));
  }

  @Test
  public void testAuth0GetUsername() throws Exception {
    Event e;
    Parser p = getTestParser();
    assertNotNull(p);

    String usernameExists =
        "{\"_id\": \"5734829321d6731f1b94e07a\",\"log_id\": null,\"date\": "
            + "\"2019-06-29T17:44:08.135Z\",\"type\": \"s\",\"client_id\": \"XXXXXXXXXXXX\","
            + "\"details\": {\"prompts\": [{\"user_id\": \"ad|Enterprise-LDAP|wriker\",\"user_name\": \"wriker@mozilla.com\"}]}}";

    e = p.parse(usernameExists);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    Auth0 usernameExistsPayload = e.getPayload();
    assertEquals("wriker@mozilla.com", usernameExistsPayload.getUsername());

    String promptsIsNull =
        "{\"_id\": \"5734829321d6731f1b94e07a\",\"log_id\": null,\"date\":\"2019-06-29T17:44:08.135Z\",\"type\": \"s\",\"client_id\": \"XXXXXXXXXXXX\",\"details\": {\"prompts\": null}}";

    e = p.parse(promptsIsNull);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    Auth0 promptsIsNullPayload = e.getPayload();
    assertNull(promptsIsNullPayload.getUsername());

    String promptsContainsEmptyArray =
        "{\"_id\": \"5734829321d6731f1b94e07a\",\"log_id\": null,\"date\":\"2019-06-29T17:44:08.135Z\",\"type\": \"s\",\"client_id\": \"XXXXXXXXXXXX\",\"details\": {\"prompts\": []}}";

    e = p.parse(promptsContainsEmptyArray);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.AUTH0, e.getPayloadType());
    Auth0 promptsContainsEmptyArrayPayload = e.getPayload();
    assertNull(promptsContainsEmptyArrayPayload.getUsername());
  }

  @Test
  public void testPhabricatorAudit() throws Exception {
    String buf =
        "{\"textPayload\":\"[Mon, 20 Jan 2020 16:12:49 +0000]\\t4664\\tip.us-west-2.comput"
            + "e.internal\\t216.160.83.56\\tphab-user\\tPhabricatorConduitAPIController\\tfeed.que"
            + "ry_id\\t/api/feed.query_id\\t-\\t200\\t96256\",\"insertId\":\"000000000000000\",\"r"
            + "esource\":{\"type\":\"aws_ec2_instance\",\"labels\":{\"instance_id\":\"i-08\",\""
            + "project_id\":\"phabricator\",\"aws_account\":\"000000000000\",\"region\":\"aws:u"
            + "s-west-2b\"}},\"timestamp\":\"2020-01-20T16:12:49.479690845Z\",\"labels\":{\"app"
            + "lication\":\"mozphab\",\"type\":\"webhead\",\"env\":\"devsvc\",\"ec2.amazonaws.c"
            + "om/resource_name\":\"ip.us-west-2.compute.internal\",\"stack\":\"mozphab-phabhos"
            + "t-webhead\"},\"logName\":\"projects/phabricator-prod\",\"receiveTimestamp\":\"20"
            + "20-01-20T16:12:50.459265709Z\"}";
    Parser p = getTestParser();
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.PHABRICATOR_AUDIT, e.getPayloadType());

    Phabricator d = e.getPayload();
    assertNotNull(d);
    assertEquals("phab-user", d.getUser());
    assertEquals("216.160.83.56", d.getSourceAddress());
    assertEquals("Milton", d.getSourceAddressCity());
    assertEquals("US", d.getSourceAddressCountry());
    assertEquals(47.25, d.getSourceAddressLatitude(), 0.5);
    assertEquals(-122.31, d.getSourceAddressLongitude(), 0.5);
    assertEquals("/api/feed.query_id", d.getPath());
    assertEquals("PhabricatorConduitAPIController", d.getController());
    assertEquals("feed.query_id", d.getFunction());
    assertNull(d.getReferer());
    assertEquals(200, (int) d.getStatus());
    assertEquals(1579536769000L, e.getTimestamp().getMillis());

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH_SESSION));
    assertEquals("phab-user", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("phabricator", n.getObject());
  }
}
