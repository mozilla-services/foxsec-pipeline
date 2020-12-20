package com.mozilla.secops.parser;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.input.InputElement;
import java.io.IOException;
import java.util.EnumMap;
import org.apache.beam.sdk.PipelineResult;
import org.apache.beam.sdk.metrics.MetricNameFilter;
import org.apache.beam.sdk.metrics.MetricResult;
import org.apache.beam.sdk.metrics.MetricsFilter;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.testing.TestPipeline;
import org.junit.Rule;
import org.junit.Test;

public class TestParserMetrics {

  private static ObjectMapper mapper = new ObjectMapper();

  @Rule public final transient TestPipeline pipeline = TestPipeline.fromOptions(getInputOptions());

  private static InputOptions getInputOptions() {
    InputOptions o = PipelineOptionsFactory.as(InputOptions.class);
    return o;
  }

  @Test
  public void testParserMetricsAreInitialized() {
    ParserMetrics sut = new ParserMetrics("postfix");
    sut.eventTooOld();

    for (Payload.PayloadType type : Payload.PayloadType.values()) {
      sut.eventOfPayload(type);
    }
    // nothing that can be tested here except that we can initialize
    // and increase some counters without exceptions
    assertNotNull(sut);
  }

  @Test
  public void testSimplexParserMetrics() throws IOException {
    ParserCfg cfg = new ParserCfg();

    EnumMap<Payload.PayloadType, Long> expectedResults = new EnumMap<>(Payload.PayloadType.class);
    expectedResults.put(Payload.PayloadType.GLB, 1L);
    expectedResults.put(Payload.PayloadType.OPENSSH, 5L);
    expectedResults.put(Payload.PayloadType.RAW, 1L);
    expectedResults.put(Payload.PayloadType.FXAAUTH, 1L);
    expectedResults.put(Payload.PayloadType.GUARDDUTY, 1L);
    expectedResults.put(Payload.PayloadType.CLOUDTRAIL, 1L);
    expectedResults.put(Payload.PayloadType.GCPAUDIT, 1L);

    Input input =
        new Input("project")
            .simplex()
            .withInputElement(
                new InputElement(Input.SIMPLEX_DEFAULT_ELEMENT)
                    .addFileInput("./target/test-classes/testdata/parsermetrics_mixedinput.txt")
                    .setParserConfiguration(cfg));

    input = mapper.readValue(mapper.writeValueAsString(input), Input.class);

    pipeline.apply(input.simplexRead());

    PipelineResult pResult = pipeline.run();
    pResult.waitUntilFinish();

    expectedResults.forEach(
        (payloadType, expectedCount) -> {
          Iterable<MetricResult<Long>> writes =
              pResult
                  .metrics()
                  .queryMetrics(
                      MetricsFilter.builder()
                          .addNameFilter(
                              MetricNameFilter.named("parser_default", payloadType.toString()))
                          .build())
                  .getCounters();
          Long eventCount = 0L;
          for (MetricResult<Long> x : writes) {
            eventCount += x.getCommitted();
          }
          assertEquals(
              String.format("Incorrect value for %s", payloadType.toString()),
              expectedCount,
              eventCount);
        });
  }

  @Test
  public void testMultiplexParserMetrics() throws IOException {
    ParserCfg cfg = new ParserCfg();

    EnumMap<Payload.PayloadType, Long> expectedResults = new EnumMap<>(Payload.PayloadType.class);
    expectedResults.put(Payload.PayloadType.GLB, 1L);
    expectedResults.put(Payload.PayloadType.OPENSSH, 5L);
    expectedResults.put(Payload.PayloadType.RAW, 1L);
    expectedResults.put(Payload.PayloadType.FXAAUTH, 1L);
    expectedResults.put(Payload.PayloadType.GUARDDUTY, 1L);
    expectedResults.put(Payload.PayloadType.CLOUDTRAIL, 1L);
    expectedResults.put(Payload.PayloadType.GCPAUDIT, 1L);

    Input input =
        new Input()
            .multiplex()
            .withInputElement(
                new InputElement("a")
                    .addFileInput("./target/test-classes/testdata/parsermetrics_mixedinput.txt")
                    .setParserConfiguration(cfg))
            .withInputElement(
                new InputElement("b")
                    .addFileInput("./target/test-classes/testdata/parsermetrics_mixedinput.txt")
                    .setParserConfiguration(cfg));

    pipeline.apply(input.multiplexRead());

    PipelineResult pResult = pipeline.run();
    pResult.waitUntilFinish();

    expectedResults.forEach(
        (payloadType, expectedCount) -> {
          Iterable<MetricResult<Long>> writes =
              pResult
                  .metrics()
                  .queryMetrics(
                      MetricsFilter.builder()
                          .addNameFilter(MetricNameFilter.named("parser_a", payloadType.toString()))
                          .build())
                  .getCounters();
          Long eventCount = 0L;
          for (MetricResult<Long> x : writes) {
            eventCount += x.getCommitted();
          }
          assertEquals(
              String.format("Incorrect value for %s", payloadType.toString()),
              expectedCount,
              eventCount);
        });

    expectedResults.forEach(
        (payloadType, expectedCount) -> {
          Iterable<MetricResult<Long>> writes =
              pResult
                  .metrics()
                  .queryMetrics(
                      MetricsFilter.builder()
                          .addNameFilter(MetricNameFilter.named("parser_b", payloadType.toString()))
                          .build())
                  .getCounters();
          Long eventCount = 0L;
          for (MetricResult<Long> x : writes) {
            eventCount += x.getCommitted();
          }
          assertEquals(
              String.format("Incorrect value for %s", payloadType.toString()),
              expectedCount,
              eventCount);
        });
  }
}
