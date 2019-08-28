package com.mozilla.secops.metrics;

import static org.junit.Assert.*;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.parser.CfgTick;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.Serializable;
import org.apache.beam.runners.direct.DirectOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestCfgTickGenerator implements Serializable {
  private static final long serialVersionUID = 1L;

  public TestCfgTickGenerator() {}

  public interface CfgTickGeneratorOptions extends InputOptions, DirectOptions {}

  private static CfgTickGeneratorOptions getOptions() {
    CfgTickGeneratorOptions o = PipelineOptionsFactory.as(CfgTickGeneratorOptions.class);
    o.setGenerateConfigurationTicksInterval(1);
    o.setGenerateConfigurationTicksMaximum(2L);
    o.setInputFile(new String[] {"./target/test-classes/testdata/inputtype_buffer1.txt"});
    return o;
  }

  @Rule public final transient TestPipeline pipeline = TestPipeline.fromOptions(getOptions());

  @Test
  public void cfgTickGeneratorTest() throws Exception {
    CfgTickGeneratorOptions o = getOptions();

    CfgTickBuilder builder = new CfgTickBuilder().includePipelineOptions(getOptions());

    PCollection<Event> results =
        pipeline
            .apply(Input.compositeInputAdapter(o, builder.build()))
            .apply(ParDo.of(new ParserDoFn()));

    PAssert.that(results)
        .satisfies(
            i -> {
              int cnt = 0;
              for (Event e : i) {
                if (e.getPayloadType() != Payload.PayloadType.CFGTICK) {
                  continue;
                }
                CfgTick ct = e.getPayload();
                assertEquals(
                    "./target/test-classes/testdata/inputtype_buffer1.txt",
                    ct.getConfigurationMap().get("inputFile"));
                assertEquals(
                    "1", ct.getConfigurationMap().get("generateConfigurationTicksInterval"));
                cnt++;
              }
              assertEquals(2, cnt);
              return null;
            });

    pipeline.run().waitUntilFinish();
  }
}
