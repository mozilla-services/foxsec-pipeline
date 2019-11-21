package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.awsbehavior.AwsBehavior;
import com.mozilla.secops.parser.Cloudtrail;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserTest;
import com.mozilla.secops.parser.Payload;
import java.io.IOException;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestAwsBehavior {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  public TestAwsBehavior() {}

  private AwsBehavior.AwsBehaviorOptions getTestOptions() {
    AwsBehavior.AwsBehaviorOptions ret =
        PipelineOptionsFactory.as(AwsBehavior.AwsBehaviorOptions.class);
    ret.setIdentityManagerPath("/testdata/identitymanager.json");
    ret.setCloudtrailMatcherManagerPath("/testdata/event_matchers.json");
    ret.setMaxmindCityDbPath(ParserTest.TEST_GEOIP_DBPATH);
    return ret;
  }

  @Test
  public void noopPipelineTest() throws Exception {
    p.run().waitUntilFinish();
  }

  @Test
  public void parseAndWindowTest() throws Exception {
    PCollection<String> input = TestUtil.getTestInput("/testdata/cloudtrail_buffer1.txt", p);

    PCollection<Event> res = input.apply(new AwsBehavior.ParseAndWindow(getTestOptions()));

    PAssert.that(res)
        .satisfies(
            results -> {
              assertNotNull(results);
              int cnt = 0;
              for (Event e : results) {
                cnt += 1;
                assertEquals(e.getPayloadType(), Payload.PayloadType.CLOUDTRAIL);
                Cloudtrail c = e.getPayload();
                assertNotNull(c.getUser());
              }
              assertEquals(4, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }

  @Test
  public void brokenMatcherTest() throws Exception {
    AwsBehavior.AwsBehaviorOptions options = getTestOptions();
    options.setCloudtrailMatcherManagerPath("/not-a-real-path");
    PCollection<String> input = TestUtil.getTestInput("/testdata/cloudtrail_buffer1.txt", p);

    try {
      PCollection<Alert> res =
          input
              .apply(new AwsBehavior.ParseAndWindow(options))
              .apply(new AwsBehavior.Matchers(options));
      fail("Expected an IOException");
    } catch (IOException exc) {
      assertEquals(exc.getMessage(), "cloudtrail matcher manager resource not found");
    }

    p.run().waitUntilFinish();
  }

  @Test
  public void matcherTest() throws Exception {
    AwsBehavior.AwsBehaviorOptions options = getTestOptions();
    PCollection<String> input = TestUtil.getTestInput("/testdata/cloudtrail_buffer1.txt", p);

    PCollection<Alert> res =
        input
            .apply(new AwsBehavior.ParseAndWindow(options))
            .apply(new AwsBehavior.Matchers(options));

    PAssert.that(res)
        .satisfies(
            results -> {
              int cnt = 0;
              for (Alert a : results) {
                assertEquals("awsbehavior", a.getCategory());
                assertEquals(Alert.AlertSeverity.CRITICAL, a.getSeverity());
                String actualSummary = a.getSummary();
                if (actualSummary.equals("IAM action from console without mfa by picard")) {
                  cnt++;
                  assertEquals("picard", a.getMetadataValue("user"));
                } else if (actualSummary.equals("access key created by uhura for guinan")) {
                  cnt++;
                  assertEquals("uhura", a.getMetadataValue("user"));
                  if (a.getMetadataValue("resource") != null) {
                    assertEquals("guinan", a.getMetadataValue("resource"));
                  }
                }
              }
              assertEquals(3, cnt);
              return null;
            });

    p.run().waitUntilFinish();
  }
}
