package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.ParserTest;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.IntervalWindow;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Instant;
import org.junit.Rule;
import org.junit.Test;

public class TestCustoms {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  private Customs.CustomsOptions getTestOptions() {
    Customs.CustomsOptions ret = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    ret.setMonitoredResourceIndicator("test");
    ret.setMaxmindDbPath(ParserTest.TEST_GEOIP_DBPATH);
    return ret;
  }

  public TestCustoms() {}

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void parseTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_rl_badlogin_simple1.txt", p);

    PCollection<Long> count =
        input
            .apply(ParDo.of(new ParserDoFn()))
            .apply(Combine.globally(Count.<Event>combineFn()).withoutDefaults());

    PAssert.that(count).containsInAnyOrder(5L);

    p.run().waitUntilFinish();
  }

  @Test
  public void rlLoginFailureSourceAddressTest() throws Exception {
    PCollection<String> input =
        TestUtil.getTestInput("/testdata/customs_rl_badlogin_simple1.txt", p);

    CustomsCfg cfg = CustomsCfg.loadFromResource("/customs/customsdefault.json");
    // Force use of event timestamp for testing purposes
    cfg.setTimestampOverride(true);

    PCollection<Alert> alerts =
        input
            .apply(
                ParDo.of(
                    new ParserDoFn()
                        .withConfiguration(ParserCfg.fromInputOptions(getTestOptions()))))
            .apply(new Customs.Detectors(cfg, getTestOptions()));

    PCollection<Long> count =
        alerts.apply(Combine.globally(Count.<Alert>combineFn()).withoutDefaults());
    PAssert.that(count)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(900000L)))
        .containsInAnyOrder(1L);

    PAssert.that(alerts)
        .inWindow(new IntervalWindow(new Instant(0L), new Instant(900000L)))
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert a : x) {
                assertEquals("customs", a.getCategory());
                assertEquals("spock@mozilla.com", a.getMetadataValue("accountid"));
                assertEquals("127.0.0.1", a.getMetadataValue("sourceaddress"));
                assertEquals("5", a.getMetadataValue("count"));
                assertEquals("3", a.getMetadataValue("threshold"));
                assertEquals(
                    "rl_login_failure_sourceaddress_accountid",
                    a.getMetadataValue("customs_category"));
                cnt++;
              }
              assertEquals(1, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
