package com.mozilla.secops.input;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.Raw;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Count;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestInputJson {
  public TestInputJson() {}

  private static ObjectMapper mapper = new ObjectMapper();

  @Rule public final transient TestPipeline pipeline = TestPipeline.fromOptions(getInputOptions());

  private static InputOptions getInputOptions() {
    InputOptions o = PipelineOptionsFactory.as(InputOptions.class);
    return o;
  }

  @Test
  public void testJsonSerializeInput() throws Exception {
    EventFilter filter = new EventFilter();
    filter.addRule(
        new EventFilterRule()
            .wantSubtype(Payload.PayloadType.RAW)
            .addPayloadFilter(
                new EventFilterPayload(Raw.class)
                    .withStringMatch(EventFilterPayload.StringProperty.RAW_RAW, "test")));

    Input input =
        new Input("project")
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt")
                    .setParserConfiguration(new ParserCfg())
                    .setEventFilter(filter))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt")
                    .setParserConfiguration(new ParserCfg())
                    .setEventFilter(filter));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<KV<String, Event>> results = pipeline.apply(input.multiplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(20L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testJsonSerializeInputRaw() throws Exception {
    Input input =
        new Input("project")
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt"))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt"));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<KV<String, String>> results = pipeline.apply(input.multiplexReadRaw());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(40L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testJsonSerializeInputSimplexRaw() throws Exception {
    Input input =
        new Input("project")
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt"));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<String> results = pipeline.apply(input.simplexReadRaw());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(20L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testJsonSerializeInputSimplex() throws Exception {
    Input input =
        new Input("project")
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/inputtype_buffer3.txt")
                    .setParserConfiguration(new ParserCfg()));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<Event> results = pipeline.apply(input.simplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(20L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testJsonSerializeInputSimplexProjectFilterInclude() throws Exception {
    ParserCfg cfg = new ParserCfg();
    cfg.setStackdriverProjectFilter("test");
    Input input =
        new Input("project")
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/httpreq_errorrate1.txt")
                    .setParserConfiguration(cfg));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<Event> results = pipeline.apply(input.simplexRead());
    PCollection<Long> count = results.apply(Count.globally());

    PAssert.thatSingleton(count).isEqualTo(55L);

    pipeline.run().waitUntilFinish();
  }

  @Test
  public void testJsonSerializeInputSimplexProjectFilterExclude() throws Exception {
    ParserCfg cfg = new ParserCfg();
    cfg.setStackdriverProjectFilter("notmatched");
    Input input =
        new Input("project")
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/httpreq_errorrate1.txt")
                    .setParserConfiguration(cfg));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    PCollection<Event> results = pipeline.apply(input.simplexRead());
    PAssert.that(results).empty();

    pipeline.run().waitUntilFinish();
  }
}
