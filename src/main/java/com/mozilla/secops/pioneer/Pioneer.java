package com.mozilla.secops.pioneer;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.GcpVpcFlow;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.DateTime;
import org.joda.time.Duration;

/** Pioneer analysis pipeline */
public class Pioneer implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Generate alerts if flow logs indicate a certain volume of data has been transferred within a
   * specified period of time.
   *
   * <p>This transform currently keys on very specific attributes of the ingested flows, namely
   * everything other than a flow with a source port of 22 is excluded. This could be adapted to be
   * more generic in the future if required.
   */
  public static class PioneerExfiltration extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final int thresholdBytes;
    private final int thresholdMillis;
    private final String monitoredResource;

    // The gap duration for us to consider a flow session as expired
    private static final Duration SESSION_GAP_DURATION = Duration.standardMinutes(30);

    // How often to fire early panes
    private static final Duration SESSION_PANE_TRIGGER_DELAY = Duration.standardMinutes(5);

    public String getTransformDoc() {
      return "";
    }

    /**
     * Construct new PioneerExfiltration
     *
     * @param options Pipeline options
     */
    public PioneerExfiltration(PioneerOptions options) {
      thresholdBytes = options.getExfiltrationThresholdBytes();
      thresholdMillis = options.getExfiltrationThresholdSeconds() * 1000;
      monitoredResource = options.getMonitoredResourceIndicator();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(
              "filter flows",
              ParDo.of(
                  new DoFn<Event, KV<String, Event>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();

                      if (!e.getPayloadType().equals(Payload.PayloadType.GCP_VPC_FLOW)) {
                        return;
                      }
                      GcpVpcFlow d = e.getPayload();
                      if (d == null) {
                        return;
                      }

                      // Make sure we have all the required fields
                      if (d.getSrcIp() == null
                          || d.getSrcPort() == null
                          || d.getDestIp() == null
                          || d.getDestPort() == null) {
                        return;
                      }

                      if (d.getSrcPort() != 22) {
                        return;
                      }

                      // For the key, make use of the source elements of the flow record so we can
                      // group all active sessions for the same instance
                      c.output(KV.of(String.join("-", d.getSrcIp(), d.getSrcPort().toString()), e));
                    }
                  }))
          .apply(
              "window for sessions",
              Window.<KV<String, Event>>into(Sessions.withGapDuration(SESSION_GAP_DURATION))
                  .triggering(
                      Repeatedly.forever(
                          AfterWatermark.pastEndOfWindow()
                              .withEarlyFirings(
                                  AfterProcessingTime.pastFirstElementInPane()
                                      .plusDelayOf(SESSION_PANE_TRIGGER_DELAY))))
                  .withAllowedLateness(Duration.ZERO)
                  .accumulatingFiredPanes())
          .apply(GroupByKey.<String, Event>create())
          .apply(
              "analyze",
              ParDo.of(
                  new DoFn<KV<String, Iterable<Event>>, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      String key = c.element().getKey();

                      // Sort the flow events for this session by timestamp
                      List<Event> events =
                          StreamSupport.stream(c.element().getValue().spliterator(), false)
                              .sorted((e1, e2) -> e1.getTimestamp().compareTo(e2.getTimestamp()))
                              .collect(Collectors.toList());

                      for (int i = 0; i < events.size(); i++) {
                        DateTime start = events.get(i).getTimestamp();
                        DateTime endpoint = start.plusMillis(thresholdMillis);

                        // From our current index, loop forward until we move outside our time
                        // based threshold
                        int j;
                        for (j = i; j < events.size(); j++) {
                          if (events.get(j).getTimestamp().isAfter(endpoint)) {
                            break;
                          }
                        }
                        if (j == events.size()) {
                          j--;
                        }

                        // Calculate the byte count across the resulting range
                        int bytes = 0;
                        GcpVpcFlow sample = null;
                        for (int k = i; k <= j; k++) {
                          GcpVpcFlow d = events.get(k).getPayload();
                          if (sample == null) {
                            sample = d;
                          }
                          bytes += d.getBytesSent();
                        }

                        if (bytes >= thresholdBytes) {
                          // Generate an alert for this flow and break
                          Alert alert = new Alert();
                          alert.setCategory("pioneer");
                          alert.setSubcategory("exfiltration");
                          alert.setNotifyMergeKey("exfiltration");
                          alert.addMetadata(AlertMeta.Key.SOURCEADDRESS, sample.getSrcIp());
                          alert.addMetadata(AlertMeta.Key.BYTES, Integer.toString(bytes));
                          alert.addMetadata(
                              AlertMeta.Key.START, events.get(i).getTimestamp().toString());
                          alert.addMetadata(
                              AlertMeta.Key.END, events.get(j).getTimestamp().toString());
                          alert.addMetadata(
                              AlertMeta.Key.INSTANCE_NAME, sample.getSrcInstanceName());
                          alert.setSummary(
                              String.format(
                                  "%s data exfiltration %s:%d -> %s:%d (%s)",
                                  monitoredResource,
                                  sample.getSrcIp(),
                                  sample.getSrcPort(),
                                  sample.getDestIp(),
                                  sample.getDestPort(),
                                  sample.getSrcInstanceName()));
                          c.output(alert);
                          break;
                        }
                      }
                    }
                  }))
          .apply(new GlobalTriggers<Alert>(5));
    }
  }

  /**
   * Execute Pioneer pipeline
   *
   * @param p Pipeline
   * @param input Input collection
   * @param options PioneerOptions
   * @return Collection of Alert objects
   * @throws IOException IOException
   */
  public static PCollection<Alert> executePipeline(
      Pipeline p, PCollection<String> input, PioneerOptions options) throws IOException {
    ParserCfg cfg = ParserCfg.fromInputOptions(options);

    EventFilter filter = new EventFilter().passConfigurationTicks();
    filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.GCP_VPC_FLOW));

    PCollection<Event> parsed =
        input.apply(
            ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)));

    // Using a list here isn't required since we have a single analysis branch, but it has been
    // added to simplify the addition of new transforms later
    PCollectionList<Alert> resultsList = PCollectionList.empty(p);

    resultsList = resultsList.and(parsed.apply("exfiltration", new PioneerExfiltration(options)));

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      resultsList =
          resultsList.and(
              parsed
                  .apply("cfgtick processor", ParDo.of(new CfgTickProcessor("pioneer-cfgtick")))
                  .apply(new GlobalTriggers<Alert>(5)));
    }

    return resultsList.apply("flatten output", Flatten.<Alert>pCollections());
  }

  /** Runtime options for {@link Pioneer} pipeline. */
  public interface PioneerOptions extends PipelineOptions, IOOptions {
    @Description("Data threshold for exfiltration alert trigger; bytes")
    @Default.Integer(1000000000) // 1 GB
    Integer getExfiltrationThresholdBytes();

    void setExfiltrationThresholdBytes(Integer value);

    @Description("Time threshold for exfiltration alert trigger; seconds")
    @Default.Integer(1800) // 30 minutes
    Integer getExfiltrationThresholdSeconds();

    void setExfiltrationThresholdSeconds(Integer value);
  }

  /**
   * Build a configuration tick for Pioneer given pipeline options
   *
   * @param options Pipeline options
   * @return String
   * @throws IOException IOException
   */
  public static String buildConfigurationTick(PioneerOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    return b.build();
  }

  private static void runPioneer(PioneerOptions options) throws IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input =
        p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)));
    PCollection<Alert> alerts = executePipeline(p, input, options);

    alerts
        .apply("alert formatter", ParDo.of(new AlertFormatter(options)))
        .apply("alert conversion", MapElements.via(new AlertFormatter.AlertToString()))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   * @throws IOException IOException
   */
  public static void main(String[] args) throws IOException {
    PipelineOptionsFactory.register(PioneerOptions.class);
    PioneerOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(PioneerOptions.class);
    runPioneer(options);
  }
}
