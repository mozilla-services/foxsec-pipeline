package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.IOOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.ETDBeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;

/** Implements various transforms on GCP's {@link EventThreatDetectionFinding} Events */
public class ETDTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for ETD Transforms */
  public interface Options extends PipelineOptions, IOOptions {
    @Description("Ignore ETD Findings for any finding rules that match regex (multiple allowed)")
    String[] getIgnoreETDFindingRuleRegex();

    void setIgnoreETDFindingRuleRegex(String[] value);

    @Description("Escalate ETD Findings for any finding rules that match regex (multiple allowed)")
    String[] getEscalateETDFindingRuleRegex();

    void setEscalateETDFindingRuleRegex(String[] value);
  }

  /** Extract ETD Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<Pattern> exclude;

    /**
     * static initializer for filter
     *
     * @param opts {@link Options} pipeline options
     */
    public ExtractFindings(Options opts) {
      String[] ignoreRegexes = opts.getIgnoreETDFindingRuleRegex();
      exclude = new ArrayList<Pattern>();
      if (ignoreRegexes != null) {
        for (String s : ignoreRegexes) {
          exclude.add(Pattern.compile(s));
        }
      }
    }

    @Override
    public PCollection<Event> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, Event>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  Event e = c.element();
                  if (!e.getPayloadType().equals(Payload.PayloadType.ETD)) {
                    return;
                  }
                  ETDBeta etdb = e.getPayload();
                  if (etdb == null) {
                    return;
                  }
                  EventThreatDetectionFinding f = etdb.getFinding();
                  if (f == null
                      || f.getDetectionCategory() == null
                      || f.getDetectionCategory().getRuleName() == null) {
                    return;
                  }
                  for (Pattern p : exclude) {
                    if (p.matcher(f.getDetectionCategory().getRuleName()).matches()) {
                      return;
                    }
                  }
                  c.output(e);
                }
              }));
    }
  }

  /** Generate Alerts for relevant ETD Finding Events */
  public static class GenerateAlerts extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:gcp";

    private List<Pattern> escalate;
    private String critNotifyEmail;

    /**
     * static initializer for alert generation / escalation
     *
     * @param opts {@link Options} pipeline options
     */
    public GenerateAlerts(Options opts) {
      critNotifyEmail = opts.getCriticalNotificationEmail();
      String[] escalateRegexes = opts.getEscalateETDFindingRuleRegex();

      escalate = new ArrayList<Pattern>();
      if (escalateRegexes != null) {
        for (String s : escalateRegexes) {
          escalate.add(Pattern.compile(s));
        }
      } else {
        escalate.add(Pattern.compile(".+"));
      }
    }

    private void addEscalationMetadata(Alert a) {
      if (critNotifyEmail != null) {
        a.addMetadata("notify_email_direct", critNotifyEmail);
      }
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, Alert>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  Event e = c.element();
                  if (!e.getPayloadType().equals(Payload.PayloadType.ETD)) {
                    return;
                  }
                  ETDBeta etdb = e.getPayload();
                  if (etdb == null) {
                    return;
                  }
                  EventThreatDetectionFinding f = etdb.getFinding();
                  if (f == null) {
                    return;
                  }
                  Alert a = new Alert();
                  a.setSummary(
                      String.format(
                          "suspicious activity detected in gcp org %s project %s",
                          f.getSourceId().getCustomerOrganizationNumber(),
                          f.getProperties().getProject_id()));
                  a.setTimestamp(DateTime.parse(f.getEventTime()));
                  a.setCategory(alertCategory);
                  a.setSeverity(Alert.AlertSeverity.CRITICAL);
                  if (f.getProperties().getLocation() != null) {
                    a.addMetadata("location", f.getProperties().getLocation());
                  }
                  a.addMetadata("indicator", f.getDetectionCategory().getIndicator());
                  a.addMetadata("rule_name", f.getDetectionCategory().getRuleName());
                  a.addMetadata("technique", f.getDetectionCategory().getTechnique());
                  a.addMetadata("project_number", f.getSourceId().getProjectNumber());
                  a.addMetadata("project_id", f.getProperties().getProject_id());
                  for (Pattern p : escalate) {
                    if (p.matcher(f.getDetectionCategory().getRuleName()).matches()) {
                      addEscalationMetadata(a);
                      break;
                    }
                  }
                  c.output(a);
                }
              }));
    }
  }
}
