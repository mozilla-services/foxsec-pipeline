package com.mozilla.secops.parser;

import static org.junit.Assert.*;

import com.carrotsearch.junitbenchmarks.BenchmarkOptions;
import com.carrotsearch.junitbenchmarks.BenchmarkRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

public class ParserBenchmark {
  @Rule public TestRule benchmarkRun = new BenchmarkRule();

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkGlb() throws Exception {
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
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkNginxVariant2DisableStrip() throws Exception {
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
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    cfg.setDisableMozlogStrip(true);
    cfg.setDisableCloudwatchStrip(true);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkNginxVariant2() throws Exception {
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
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkFxaAuth() throws Exception {
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
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkFxaAuthDisableStripCloudwatch() throws Exception {
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
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    // We need to handle the Mozlog header, so just disable Cloudwatch
    cfg.setDisableCloudwatchStrip(true);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }

  @BenchmarkOptions(benchmarkRounds = 20, warmupRounds = 5)
  @Test
  public void benchmarkAlert() throws Exception {
    String buf =
        "{\"severity\":\"info\",\"id\":\"3ddcbcff-f334-4189-953c-14a34a2cc030\",\"summa"
            + "ry\":\"test suspicious account creation, 216.160.83.56 3\",\"category\":\"cust"
            + "oms\",\"timestamp\":\"1970-01-01T00:00:00.000Z\",\"metadata\":[{\"key\":\"noti"
            + "fy_merge\",\"value\":\"account_creation_abuse\"},{\"key\":\"customs_category\""
            + ",\"value\":\"account_creation_abuse\"},{\"key\":\"sourceaddress\",\"value\":\""
            + "216.160.83.56\"},{\"key\":\"count\",\"value\":\"3\"},{\"key\":\"email\",\"valu"
            + "e\":\"user@mail.com, user.1@mail.com, user.1.@mail.com\"}]}";
    ParserCfg cfg = new ParserCfg();
    cfg.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    Parser p = new Parser(cfg);

    for (int i = 0; i < 5000; i++) {
      assertNotNull(p.parse(buf));
    }
  }
}
