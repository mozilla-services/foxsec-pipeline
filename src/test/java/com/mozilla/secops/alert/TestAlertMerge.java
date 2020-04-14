package com.mozilla.secops.alert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestAlertMerge {
  @Rule public final transient TestPipeline p = TestPipeline.create();

  public TestAlertMerge() {}

  @Test
  public void alertMergeTest() throws Exception {
    ArrayList<String> inputs = new ArrayList<>();

    Alert a = new Alert();
    a.setSummary("test1");
    a.setNotifyMergeKey("key");
    inputs.add(a.toJSON());

    a = new Alert();
    a.setSummary("test2");
    inputs.add(a.toJSON());

    a = new Alert();
    a.setSummary("test3");
    a.setNotifyMergeKey("key");
    inputs.add(a.toJSON());

    a = new Alert();
    a.setSummary("test4");
    a.setNotifyMergeKey("something");
    inputs.add(a.toJSON());

    PCollection<Alert> output = p.apply(Create.of(inputs)).apply(new AlertIO.AlertNotifyMerge());

    PAssert.that(output)
        .satisfies(
            x -> {
              int cnt = 0;
              for (Alert b : x) {
                switch (b.getSummary()) {
                  case "test2":
                  case "test4":
                    assertNull(b.getMetadataValue(AlertMeta.Key.NOTIFY_MERGED_COUNT));
                    break;
                  case "test1 (1 similar alerts)":
                  case "test3 (1 similar alerts)":
                    assertEquals("2", b.getMetadataValue(AlertMeta.Key.NOTIFY_MERGED_COUNT));
                    break;
                  default:
                    fail("unexpected alert summary");
                    break;
                }
                cnt++;
              }
              assertEquals(3, cnt); // We should have 3, since one will have been merged
              return null;
            });

    p.run().waitUntilFinish();
  }
}
