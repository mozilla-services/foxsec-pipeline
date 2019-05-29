package com.mozilla.secops.parser;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class GroovyEventFilterTest {
  private final String httpRequest1 =
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

  private final String openssh1 =
      "Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12"
          + "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  public GroovyEventFilterTest() {}

  @Test
  public void testHttpRequestFilterBasic() throws Exception {
    GroovyEventFilter f =
        new GroovyEventFilter(
            "/groovy/filter.groovy", "httpRequest", new GroovyEventFilterOptions());
    f.prepare();

    Parser p = new Parser();
    Event e = p.parse(httpRequest1);
    assertTrue(f.matches(e));

    e = p.parse(openssh1);
    assertFalse(f.matches(e));
  }
}
