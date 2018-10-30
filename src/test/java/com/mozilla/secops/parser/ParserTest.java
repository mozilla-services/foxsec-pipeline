package com.mozilla.secops.parser;

import org.junit.Test;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.maxmind.geoip2.model.CityResponse;

import org.joda.time.DateTime;

public class ParserTest {
    public ParserTest() {
    }

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
        String buf = "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource" +
            "_name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\"" +
            ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"99999999999999" +
            "99999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\"te" +
            "xtPayload\":\"test\",\"timestamp\":\"2018-09-18T22:15:38Z\"}";
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
    public void testOpenSSHRaw() throws Exception {
        String buf = "Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12" +
            "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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
        assertEquals(Normalized.Type.AUTH, n.getType());
        assertEquals("riker", n.getSubjectUser());
        assertEquals("127.0.0.1", n.getSourceAddress());
        assertEquals("emit-bastion", n.getObject());
    }

    @Test
    public void testOpenSSHStackdriver() throws Exception {
        String buf = "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_" +
            "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\"" +
            ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999" +
            "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\"" +
            "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12" +
            "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp" +
            "\":\"2018-09-18T22:15:38Z\"}";
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
        assertEquals(Normalized.Type.AUTH, n.getType());
        assertEquals("riker", n.getSubjectUser());
        assertEquals("127.0.0.1", n.getSourceAddress());
    }

    @Test
    public void testOpenSSHStackdriverGeo() throws Exception {
        String buf = "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_" +
            "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\"" +
            ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999" +
            "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\"" +
            "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from " +
            "216.160.83.56 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp" +
            "\":\"2018-09-18T22:15:38Z\"}";
        Parser p = new Parser();
        assertNotNull(p);
        assertTrue(p.geoIpUsingTest());
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
        assertEquals(Normalized.Type.AUTH, n.getType());
        assertEquals("riker", n.getSubjectUser());
        assertEquals("216.160.83.56", n.getSourceAddress());
        assertEquals("Milton", n.getSourceAddressCity());
        assertEquals("US", n.getSourceAddressCountry());
    }

    @Test
    public void testGLB() throws Exception {
        String buf = "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":" +
            "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt" +
            "ps://send.firefox.com/public/locales/en-US/send.js\",\"responseSize\":\"2692\"," +
            "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M" +
            "ac OS X 10_13_3)" +
            "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@type\":\"type.googleapis.com/" +
            "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent" +
            "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim" +
            "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_" +
            "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-" +
            "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-" +
            "97\",\"url_map_name\":\"k8s-um-prod" +
            "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}" +
            ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:" +
            "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAA\"}";
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
        assertEquals("2018-09-28T18:55:12.469Z", e.getTimestamp().toString());
        assertEquals(200, (int)g.getStatus());
    }

    @Test
    public void testStackdriverJsonNoType() throws Exception {
        // Verify Stackdriver message with a JSON payload and no @type field is returned as a
        // raw event.
        String buf = "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":" +
            "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt" +
            "ps://send.firefox.com/public/locales/en-US/send.js\",\"responseSize\":\"2692\"," +
            "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M" +
            "ac OS X 10_13_3)" +
            "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@usuallytype\":\"type.googleapis.com/" +
            "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent" +
            "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim" +
            "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_" +
            "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-" +
            "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-" +
            "97\",\"url_map_name\":\"k8s-um-prod" +
            "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}" +
            ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018-09-28T18:55:" +
            "12.469373944Z\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAA\"}";
        Parser p = new Parser();
        assertNotNull(p);
        Event e = p.parse(buf);
        assertNotNull(e);
        assertEquals(Payload.PayloadType.RAW, e.getPayloadType());
    }

    @Test
    public void testGLBInvalidTimestamp() throws Exception {
        String buf = "{\"httpRequest\":{\"referer\":\"https://send.firefox.com/\",\"remoteIp\":" +
            "\"127.0.0.1\",\"requestMethod\":\"GET\",\"requestSize\":\"43\",\"requestUrl\":\"htt" +
            "ps://send.firefox.com/public/locales/en-US/send.js\",\"responseSize\":\"2692\"," +
            "\"serverIp\":\"10.8.0.3\",\"status\":200,\"userAgent\":\"Mozilla/5.0 (Macintosh; Intel M" +
            "ac OS X 10_13_3)" +
            "\"},\"insertId\":\"AAAAAAAAAAAAAAA\",\"jsonPayload\":{\"@type\":\"type.googleapis.com/" +
            "google.cloud.loadbalancing.type.LoadBalancerLogEntry\",\"statusDetails\":\"response_sent" +
            "_by_backend\"},\"logName\":\"projects/moz/logs/requests\",\"receiveTim" +
            "estamp\":\"2018-09-28T18:55:12.840306467Z\",\"resource\":{\"labels\":{\"backend_service_" +
            "name\":\"\",\"forwarding_rule_name\":\"k8s-fws-prod-" +
            "6cb3697\",\"project_id\":\"moz\",\"target_proxy_name\":\"k8s-tps-prod-" +
            "97\",\"url_map_name\":\"k8s-um-prod" +
            "-app-1\",\"zone\":\"global\"},\"type\":\"http_load_balancer\"}" +
            ",\"severity\":\"INFO\",\"spanId\":\"AAAAAAAAAAAAAAAA\",\"timestamp\":\"2018" +
            "-1-1\",\"trace\":\"projects/moz/traces/AAAAAAAAAAAAAAAAAAAAAA" +
            "AAAAAAAAAA\"}";
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
    public void testGeoIp() throws Exception {
        Parser p = new Parser();
        assertNotNull(p);
        assertTrue(p.geoIpUsingTest());
        CityResponse resp = p.geoIp("216.160.83.56");
        assertNotNull(resp);
        assertEquals("US", resp.getCountry().getIsoCode());
        assertEquals("Milton", resp.getCity().getName());
    }
}
