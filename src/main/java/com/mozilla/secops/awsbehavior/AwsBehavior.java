package com.mozilla.secops.awsbehavior;

import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.parser.Cloudtrail;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.regex.PatternSyntaxException;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AwsBehavior implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Transform to parse a {@link PCollection} containing events as strings and emit a {@link
   * PCollection} of {@link Event} objects after filtering out events that are not {@link
   * Cloudtrail} events
   *
   * <p>The output is windowed in the global window with a trigger which fires every 10 seconds.
   */
  public static class ParseAndWindow extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private final ParserCfg cfg;

    /**
     * Static initializer for {@link ParseAndWindow} using specified pipeline options
     *
     * @param options Pipeline options
     */
    public ParseAndWindow(AwsBehaviorOptions options) {
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantSubtype(Payload.PayloadType.CLOUDTRAIL));

      return col.apply(ParDo.of(new ParserDoFn().withConfiguration(cfg)))
          .apply(EventFilter.getTransform(filter))
          .apply(new GlobalTriggers<Event>(10));
    }
  }

  /**
   * Tranform to take a specific {@link CloudtrailMatcher} and a {@link PCollection} of cloudtrail
   * events and emit a {@link PCollection} of {@link Alert} objects constructed for each event that
   * matches the {@link CloudtrailMatcher}
   */
  public static class Matcher extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private CloudtrailMatcher cm;
    private EventFilter filter;

    private Logger log;

    public Matcher(CloudtrailMatcher cm) {
      this.cm = cm;
      log = LoggerFactory.getLogger(Matcher.class);
      this.filter = new EventFilter();
      try {
        this.filter.addRule(cm.toEventFilterRule());
      } catch (CloudtrailMatcher.UnknownStringPropertyException exc) {
        log.error(
            "CloudtrailMatcher with the description '{}' threw an UnknownStringPropertyException: {}",
            cm.getDescription(),
            exc.getMessage());
      } catch (PatternSyntaxException exc) {
        log.error(
            "CloudtrailMatcher with the description '{}' threw an PatternSyntaxException: {}",
            cm.getDescription(),
            exc.getMessage());
      }
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

                      alert.setSeverity(Alert.AlertSeverity.CRITICAL);
                      alert.setCategory("awsbehavior");

                      Cloudtrail ct = e.getPayload();
                      String alertSummary =
                          String.format("%s by %s", cm.getDescription(), ct.getUser());
                      alert.addMetadata("user", ct.getUser());
                      if (cm.getResource() != null) {
                        alertSummary =
                            String.format(
                                "%s for %s", alertSummary, ct.getResource(cm.getResource()));
                        alert.addMetadata("resource", ct.getResource(cm.getResource()));
                      }
                      alert.setSummary(alertSummary);

                      if (!alert.hasCorrectFields()) {
                        throw new IllegalArgumentException("alert has invalid field configuration");
                      }

                      c.output(alert);
                    }
                  }));
    }
  }

  /**
   * High level transform for invoking each of the matcher transforms after reading in the config
   * with {@link CloudtrailMatcherManager}
   */
  public static class Matchers extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private final String cmmanagerPath;
    private CloudtrailMatcherManager cmmanager;
    private Logger log;

    public Matchers(AwsBehaviorOptions options) throws IOException {
      log = LoggerFactory.getLogger(Matchers.class);
      cmmanagerPath = options.getCloudtrailMatcherManagerPath();
      try {
        cmmanager = CloudtrailMatcherManager.loadFromResource(cmmanagerPath);
      } catch (IOException exc) {
        log.error(
            "loading cloudtrail matcher manager from resource at {} failed, {}",
            cmmanagerPath,
            exc.getMessage());
        throw exc;
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
    @Description("Override default identity manager configuration; resource path")
    String getIdentityManagerPath();

    void setIdentityManagerPath(String value);

    @Description("Cloudtrail matcher manager configuration; resource path")
    @Default.String("/awsbehavior/event_matchers.json")
    String getCloudtrailMatcherManagerPath();

    void setCloudtrailMatcherManagerPath(String value);
  }

  private static void runAwsBehavior(AwsBehaviorOptions options)
      throws IllegalArgumentException, IOException {
    Pipeline p = Pipeline.create(options);

    PCollection<Alert> alerts =
        p.apply("input", new CompositeInput(options))
            .apply("parse and window", new ParseAndWindow(options))
            .apply(new Matchers(options));

    alerts
        .apply(ParDo.of(new AlertFormatter(options)))
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
