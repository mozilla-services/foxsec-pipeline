package com.mozilla.secops.awsbehavior;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.FixedWindows;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AwsBehavior implements Serializable {
  private static final long serialVersionUID = 1L;

  public static class ParseAndWindow extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CLOUDTRAIL));

      return col.apply(ParDo.of(new ParserDoFn()))
          .apply(EventFilter.getTransform(filter))
          .apply(Window.<Event>into(FixedWindows.of(Duration.standardMinutes(5))));
    }
  }

  public static class Matcher extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private CloudtrailMatcher cm;
    private EventFilter filter;

    private Logger log;

    public Matcher(CloudtrailMatcher cm) {
      this.cm = cm;
      log = LoggerFactory.getLogger(Matcher.class);
      this.filter = new EventFilter();
      this.filter.addRule(cm.toEventFilterRule());
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      return col.apply(EventFilter.getTransform(filter))
          .apply(
              ParDo.of(
                  new DoFn<Event, Alert>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();
                      Alert alert = new Alert();
                      // TODO
                      alert.setSeverity(Alert.AlertSeverity.CRITICAL);
                      alert.setSummary(cm.getDescription());
                      alert.setCategory("AwsBehavior");
                      alert.addToPayload(cm.getDescription());
                      c.output(alert);
                    }
                  }));
    }
  }

  public static class Matchers extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final String cmmanagerPath;
    private CloudtrailMatcherManager cmmanager;
    private Logger log;

    public Matchers(AwsBehaviorOptions options) {
      log = LoggerFactory.getLogger(Matchers.class);
      cmmanagerPath = options.getCloudtrailMatcherManagerPath();
      try {
        cmmanager = CloudtrailMatcherManager.loadFromResource(cmmanagerPath);
      } catch (IOException exc) {
        log.error(
            "loading cloudtrail matcher manager from resource at {} failed, {}",
            cmmanagerPath,
            exc.getMessage());
      }
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> col) {
      PCollectionList<Alert> alerts = PCollectionList.empty(col.getPipeline());
      for (CloudtrailMatcher cm : cmmanager.getEventMatchers()) {
        alerts = alerts.and(col.apply(cm.getDescription(), new Matcher(cm)));
      }
      PCollection<Alert> ret = alerts.apply(Flatten.<Alert>pCollections());
      return ret;
    }
  }

  /** Runtime options for {@link AwsBehavior} pipeline. */
  public interface AwsBehaviorOptions extends PipelineOptions, InputOptions, OutputOptions {
    @Description("Identity manager configuration; resource path")
    @Default.String("/identitymanager.json")
    String getIdentityManagerPath();

    void setIdentityManagerPath(String value);

    @Description("Cloudtrail matcher manager configuration; resource path")
    @Default.String("/event_matchers.json")
    String getCloudtrailMatcherManagerPath();

    void setCloudtrailMatcherManagerPath(String value);
  }

  private static void runAwsBehavior(AwsBehaviorOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    PCollection<Alert> alerts =
        p.apply("input", options.getInputType().read(p, options))
            .apply("parse and window", new ParseAndWindow())
            .apply(new Matchers(options));

    alerts
        .apply(ParDo.of(new AlertFormatter()))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(AwsBehaviorOptions.class);
    AwsBehaviorOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(AwsBehaviorOptions.class);
    runAwsBehavior(options);
  }
}
