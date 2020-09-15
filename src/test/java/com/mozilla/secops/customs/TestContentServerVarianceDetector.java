package com.mozilla.secops.customs;

import com.mozilla.secops.TestUtil;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import java.util.ArrayList;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestContentServerVarianceDetector {

  public TestContentServerVarianceDetector() {}

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void getVarianceTest() throws Exception {
    PCollection<Event> input =
        TestUtil.getTestInput("/testdata/customs_contentserver.txt", pipeline)
            .apply(ParDo.of(new ParserDoFn()));
    PCollection<KV<String, Boolean>> results =
        input.apply(new ContentServerVarianceDetector.PresenceBased());

    ArrayList<KV<String, Boolean>> expected = new ArrayList<>();
    expected.add(KV.of("192.168.0.1", true));
    expected.add(KV.of("192.168.0.2", true));
    expected.add(KV.of("192.168.0.3", true));
    expected.add(KV.of("192.168.0.4", true));
    expected.add(KV.of("192.168.0.5", true));
    expected.add(KV.of("10.0.0.2", true));
    expected.add(KV.of("10.0.0.3", true));
    PAssert.that(results).containsInAnyOrder(expected);

    pipeline.run().waitUntilFinish();
  }
}
