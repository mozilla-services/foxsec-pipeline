package com.mozilla.secops;

import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestInputTypeFile {
  public TestInputTypeFile() {}

  private static InputOptions getInputOptions() {
    InputOptions o = PipelineOptionsFactory.as(InputOptions.class);
    o.setInputType(InputType.file);
    o.setInput(new String[] {"./target/test-classes/testdata/inputtype_buffer1.txt"});
    return o;
  }

  @Rule public final transient TestPipeline pipeline = TestPipeline.fromOptions(getInputOptions());

  @Test
  public void noopTextPipelineTest() throws Exception {
    pipeline.run().waitUntilFinish();
  }

  @Test
  public void readTextTest() throws Exception {
    InputOptions o = (InputOptions) pipeline.getOptions();

    PCollection<String> results = pipeline.apply(o.getInputType().read(pipeline, o));
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.that(count).containsInAnyOrder(10L);

    pipeline.run().waitUntilFinish();
  }
}
