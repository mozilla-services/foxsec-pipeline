package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.maxmind.geoip2.model.CityResponse;
import org.joda.time.DateTime;
import org.junit.Test;

public class ParserTest {
  public static final String TEST_GEOIP_DBPATH = "/testdata/GeoIP2-City-Test.mmdb";

  public ParserTest() {}

  @Test
  public void testParseZeroLength() throws Exception {
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
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
    Parser p = new Parser();
    p.enableGeoIp(TEST_GEOIP_DBPATH);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
    OpenSSH o = e.getPayload();
    assertNotNull(o);
    assertEquals("riker", o.getUser());
    assertEquals("publickey", o.getAuthMethod());
    assertEquals("216.160.83.56", o.getSourceAddress());
    assertEquals("Milton", o.getSourceAddressCity());
    assertEquals("US", o.getSourceAddressCountry());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("riker", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
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
    Parser p = new Parser();
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

    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.HTTP_REQUEST));
    assertEquals("GET", n.getRequestMethod());
    assertEquals(200, (int) n.getRequestStatus());
    assertEquals(
        "https://send.firefox.com/public/locales/en-US/send.js?test=test", n.getRequestUrl());
    assertEquals("/public/locales/en-US/send.js", n.getUrlRequestPath());
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
    Parser p = new Parser();
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
    Parser p = new Parser();
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
  public void testParseBmoAuditStackdriver() {
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
    Parser p = new Parser();
    p.enableGeoIp(TEST_GEOIP_DBPATH);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.BMOAUDIT, e.getPayloadType());
    BmoAudit b = e.getPayload();
    assertEquals("216.160.83.56", b.getRemoteIp());
    assertEquals("00000000", b.getRequestId());
    assertEquals(BmoAudit.AuditType.LOGIN, b.getAuditType());
    assertEquals("spock@mozilla.com", b.getUser());
    assertEquals("Mozilla/5.0", b.getUserAgent());
    Normalized n = e.getNormalized();
    assertNotNull(n);
    assertTrue(n.isOfType(Normalized.Type.AUTH));
    assertEquals("spock@mozilla.com", n.getSubjectUser());
    assertEquals("216.160.83.56", n.getSourceAddress());
    assertEquals("Milton", n.getSourceAddressCity());
    assertEquals("US", n.getSourceAddressCountry());
  }

  @Test
  public void testParseBmoAuditCreateBugStackdriver() {
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
    Parser p = new Parser();
    p.enableGeoIp(TEST_GEOIP_DBPATH);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.BMOAUDIT, e.getPayloadType());
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
  public void testParseMozlogDuopullBypass() {
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseDuopullBypass() {
    String buf =
        "{\"event_description_valid_secs\": 3600, \"event_description_count\": 1, "
            + "\"event_description_user_id\": \"ZZZZZZZZZZZZZZZZZZZZ\", \"event_object\": \"worf\", "
            + "\"event_timestamp\": 1530282703, \"event_username\": \"First Last\", "
            + "\"event_description_bypass_code_ids\": [\"XXXXXXXXXXXXXXXXXXXX\"], "
            + "\"event_description_bypass\": \"\", \"path\": \"/admin/v1/logs/administrator\", "
            + "\"msg\": \"duopull event\", \"event_action\": \"bypass_create\", "
            + "\"event_description_auto_generated\": true, \"event_description_remaining_uses\": 1}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
  }

  @Test
  public void testParseStackdriverTextDuopullBypass() {
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.DUOPULL, e.getPayloadType());
    Duopull d = e.getPayload();
    assertNotNull(d);
    com.mozilla.secops.parser.models.duopull.Duopull data = d.getDuopullData();
    assertEquals("duopull event", data.getMsg());
    assertEquals("bypass_create", data.getEventAction());
    assertEquals("/admin/v1/logs/administrator", data.getPath());
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
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

    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
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

    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
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
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.CLOUDTRAIL, e.getPayloadType());
    Cloudtrail ct = e.getPayload();
    assertNotNull(ct);
    assertEquals("uhura", ct.getUser());
    assertEquals("127.0.0.1", ct.getSourceAddress());
  }

  @Test
  public void testParseGcpAudit() {
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
    Parser p = new Parser();
    p.enableGeoIp(TEST_GEOIP_DBPATH);
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.GCPAUDIT, e.getPayloadType());
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
  }

  @Test
  public void testParseNginxStackdriverVariant1() {
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
    Parser p = new Parser();
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
  public void testParseNginxStackdriverVariant2() {
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
  public void testParseSecEvent() {
    String buf =
        "{\"secevent_version\":\"secevent.model.1\",\"action\":\"loginFailure\""
            + ",\"account_id\":\"q@the-q-continuum\",\"timestamp\":\"1970-01-01T00:00:00+00:00\"}";
    Parser p = new Parser();
    assertNotNull(p);
    Event e = p.parse(buf);
    assertNotNull(e);
    assertEquals(Payload.PayloadType.SECEVENT, e.getPayloadType());
    SecEvent d = e.getPayload();
    com.mozilla.secops.parser.models.secevent.SecEvent data = d.getSecEventData();
    assertNotNull(data);
    assertEquals("loginFailure", data.getAction());
    assertEquals("q@the-q-continuum", data.getActorAccountId());

    DateTime ts = e.getTimestamp();
    assertNotNull(ts);
    assertEquals(0L, ts.getMillis());
  }

  @Test
  public void testGeoIp() throws Exception {
    Parser p = new Parser();
    p.enableGeoIp(TEST_GEOIP_DBPATH);
    assertNotNull(p);
    CityResponse resp = p.geoIp("216.160.83.56");
    assertNotNull(resp);
    assertEquals("US", resp.getCountry().getIsoCode());
    assertEquals("Milton", resp.getCity().getName());
  }

  @Test
  public void testParseJsonSerializeDeserializeRaw() throws Exception {
    Parser p = new Parser();
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
    Parser p = new Parser();
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
    assertEquals(e.getTimestamp(), e2.getTimestamp());
    assertEquals(e.getPayloadType(), e2.getPayloadType());

    assertEquals(data.getEventTimestamp(), data2.getEventTimestamp());
    assertEquals(data.getEventAction(), data2.getEventAction());

    assertEquals(m.getHostname(), m2.getHostname());
    assertEquals(m.getLogger(), m2.getLogger());
  }
}
