package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressor;
import com.mozilla.secops.parser.ETDBeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.models.etd.DetectionCategory;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import com.mozilla.secops.parser.models.etd.Properties;
import com.mozilla.secops.parser.models.etd.SourceId;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Implements various transforms on GCP's {@link EventThreatDetectionFinding} Events */
public class ETDTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for ETD Transforms */
  public interface Options extends PipelineOptions, IOOptions {
    @Description("Ignore ETD Findings for any finding rules that match regex (multiple allowed)")
    String[] getIgnoreETDFindingRuleRegex();

    void setIgnoreETDFindingRuleRegex(String[] value);

    @Description(
        "Mark ETD Findings for any finding types that match regex as High severity. All others that are not ignored are considered Low severity. (multiple allowed)")
    String[] getHighETDFindingRuleRegex();

    void setHighETDFindingRuleRegex(String[] value);

    @Default.Long(60 * 15) // 15 minutes
    @Description("Suppress alert generation for repeated ETD Findings within this value")
    Long getAlertSuppressionSeconds();

    void setAlertSuppressionSeconds(Long value);
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
  public static class GenerateETDAlerts extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:gcp";

    private List<Pattern> highPatterns;
    private String critNotifyEmail;

    private Logger log;

    /**
     * static initializer for alert generation / escalation
     *
     * @param opts {@link Options} pipeline options
     */
    public GenerateETDAlerts(Options opts) {
      log = LoggerFactory.getLogger(GenerateETDAlerts.class);

      critNotifyEmail = opts.getCriticalNotificationEmail();
      String[] highRegexes = opts.getHighETDFindingRuleRegex();

      highPatterns = new ArrayList<Pattern>();
      if (highRegexes != null) {
        for (String s : highRegexes) {
          highPatterns.add(Pattern.compile(s));
        }
      }
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return "Alerts are generated based on events sent from GCP's Event Threat Detection.";
    }

    private void addBaseFindingData(Alert a, EventThreatDetectionFinding f) throws IOException {
      DetectionCategory dc = f.getDetectionCategory();
      if (dc == null) {
        throw new IOException("etd alert was missing detection category");
      } else if (dc.getIndicator() == null) {
        throw new IOException("etd alert was missing indicator");
      } else if (dc.getRuleName() == null) {
        throw new IOException("etd alert was missing rule name");
      } else if (dc.getTechnique() == null) {
        throw new IOException("etd alert was missing technique");
      }

      a.addMetadata(AlertMeta.Key.INDICATOR, dc.getIndicator());
      a.addMetadata(AlertMeta.Key.RULE_NAME, dc.getRuleName());
      a.addMetadata(AlertMeta.Key.TECHNIQUE, dc.getTechnique());

      SourceId sid = f.getSourceId();
      if (sid != null && sid.getProjectNumber() != null) {
        a.addMetadata(AlertMeta.Key.PROJECT_NUMBER, sid.getProjectNumber());
      } else {
        throw new IOException("etd alert was missing project number");
      }

      Properties prop = f.getProperties();
      if (prop != null && prop.getProject_id() != null) {
        a.addMetadata(AlertMeta.Key.PROJECT_ID, prop.getProject_id());
      } else {
        throw new IOException("etd alert was missing project id or location");
      }

      a.setSummary(
          String.format(
              "suspicious activity detected in gcp org %s project %s",
              (sid != null && sid.getCustomerOrganizationNumber() != null)
                  ? sid.getCustomerOrganizationNumber()
                  : "unknown",
              prop.getProject_id()));

      a.setCategory(alertCategory);
      a.setSeverity(Alert.AlertSeverity.CRITICAL);
    }

    private void tryAddEscalationEmail(Alert a, EventThreatDetectionFinding f) {
      DetectionCategory dc = f.getDetectionCategory();
      if (dc == null || dc.getRuleName() == null) {
        return;
      }
      for (Pattern p : highPatterns) {
        if (p.matcher(dc.getRuleName()).matches()) {
          a.addMetadata(AlertMeta.Key.ALERT_HANDLING_SEVERITY, "high");
          if (critNotifyEmail != null) {
            a.addMetadata(AlertMeta.Key.NOTIFY_EMAIL_DIRECT, critNotifyEmail);
          }
          return;
        }
      }
      a.addMetadata(AlertMeta.Key.ALERT_HANDLING_SEVERITY, "low");
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

                  try {
                    addBaseFindingData(a, f);
                  } catch (IOException exc) {
                    log.error("error processing etd alert: {}", exc.getMessage());
                    return;
                  }
                  tryAddEscalationEmail(a, f);

                  c.output(a);
                }
              }));
    }
  }

  /**
   * Suppress Alerts for repeated Event Threat Detection Findings.
   *
   * <p>We will define a "repeated finding" in ETD to mean that the source project number, the rule
   * which triggered the finding, the technique, and indicator must be the same, as well as some
   * fields which are not present for every rule e.g. location
   */
  public static class SuppressAlerts extends PTransform<PCollection<Alert>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private static Long alertSuppressionWindow;

    /**
     * static initializer for alert suppression
     *
     * @param opts {@link Options} pipeline options
     */
    public SuppressAlerts(Options opts) {
      alertSuppressionWindow = opts.getAlertSuppressionSeconds();
    }

    private String buildSuppressionStateKey(Alert a) {
      // The suppression state key for ETD findings will be a concatenation of
      // mandatory fields
      String key =
          a.getMetadataValue(AlertMeta.Key.PROJECT_NUMBER)
              + "-"
              + a.getMetadataValue(AlertMeta.Key.RULE_NAME)
              + "-"
              + a.getMetadataValue(AlertMeta.Key.TECHNIQUE)
              + "-"
              + a.getMetadataValue(AlertMeta.Key.INDICATOR);
      return key;
    }

    @Override
    @SuppressWarnings("deprecation")
    public PCollection<Alert> expand(PCollection<Alert> input) {
      return input
          .apply(
              ParDo.of(
                  new DoFn<Alert, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Alert a = c.element();
                      if (a == null) {
                        return;
                      }
                      c.output(KV.of(buildSuppressionStateKey(a), a));
                    }
                  }))
          // XXX Reshuffle here to avoid step fusion with the stateful ParDo which is causing
          // the optimizer to produce a non-updatable graph, see also
          // https://issuetracker.google.com/issues/118375066
          .apply(org.apache.beam.sdk.transforms.Reshuffle.of())
          .apply(ParDo.of(new AlertSuppressor(alertSuppressionWindow)));
    }
  }
}
