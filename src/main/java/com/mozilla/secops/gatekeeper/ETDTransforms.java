package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.IOOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertSuppressor;
import com.mozilla.secops.parser.ETDBeta;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.parser.models.etd.DetectionCategory;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import com.mozilla.secops.parser.models.etd.Evidence;
import com.mozilla.secops.parser.models.etd.Properties;
import com.mozilla.secops.parser.models.etd.SourceId;
import com.mozilla.secops.parser.models.etd.SourceLogId;
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

    private void addBaseFindingData(Alert a, EventThreatDetectionFinding f) {
      DetectionCategory dc = f.getDetectionCategory();
      if (dc != null) {
        a.tryAddMetadata("indicator", dc.getIndicator());
        a.tryAddMetadata("rule_name", dc.getRuleName());
        a.tryAddMetadata("technique", dc.getTechnique());
      }
      SourceId sid = f.getSourceId();
      if (sid != null) {
        a.tryAddMetadata("project_number", sid.getProjectNumber());
      }
      Properties prop = f.getProperties();
      if (prop != null) {
        a.tryAddMetadata("project_id", prop.getProject_id());
        a.tryAddMetadata("location", prop.getLocation());
      }
      if (sid != null
          && prop != null
          && sid.getCustomerOrganizationNumber() != null
          && prop.getProject_id() != null) {
        a.setSummary(
            String.format(
                "suspicious activity detected in gcp org %s project %s",
                sid.getCustomerOrganizationNumber(), prop.getProject_id()));
      }
      if (f.getEventTime() != null) {
        a.setTimestamp(DateTime.parse(f.getEventTime()));
      }
      a.setCategory(alertCategory);
      a.setSeverity(Alert.AlertSeverity.CRITICAL);
    }

    private void tryAddEscalationEmail(Alert a, EventThreatDetectionFinding f) {
      DetectionCategory dc = f.getDetectionCategory();
      if (dc == null || dc.getRuleName() == null) {
        return;
      }
      if (critNotifyEmail != null) {
        for (Pattern p : escalate) {
          if (p.matcher(dc.getRuleName()).matches()) {
            a.addMetadata("notify_email_direct", critNotifyEmail);
            return;
          }
        }
      }
    }

    // add informational metadata using values within finding.
    // does not assume a particular finding rule - adds everything available
    private void addRuleSpecificFindingData(Alert a, EventThreatDetectionFinding f) {
      a.tryAddMetadata("detection_priority", f.getDetectionPriority());
      a.tryAddMetadata("detection_timestap", f.getEventTime());
      Properties prop = f.getProperties();
      if (prop != null) {
        a.tryAddMetadata("subnetwork_id", prop.getSubnetwork_id());
        a.tryAddMetadata("subnetwork_name", prop.getSubnetwork_name());
        a.tryAddMetadata("ip", prop.getIp());
        List<String> doms = prop.getDomain();
        if (doms != null) {
          for (String d : doms) {
            a.tryAddMetadata("domain", d);
          }
        }
      }
      SourceId sid = f.getSourceId();
      if (sid != null) {
        a.tryAddMetadata("org_number", sid.getCustomerOrganizationNumber());
      }
      List<Evidence> evi = f.getEvidence();
      for (Evidence e : evi) {
        SourceLogId sli = e.getSourceLogId();
        if (sli != null) {
          a.tryAddMetadata("evidence_insert_id", sli.getInsertId());
          a.tryAddMetadata("evidence_timestamp", sli.getTimestamp());
        }
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

                  addBaseFindingData(a, f);
                  addRuleSpecificFindingData(a, f);
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

    // the suppression state key for ETD findings will be a concatenation of
    // some mandatory and some optional fields
    private String buildSuppressionStateKey(Alert a) {
      String key =
          a.getMetadataValue("project_number")
              + "-"
              + a.getMetadataValue("rule_name")
              + "-"
              + a.getMetadataValue("technique")
              + "-"
              + a.getMetadataValue("indicator");

      if (a.getMetadataValue("location") != null) {
        key = key + "-" + a.getMetadataValue("location");
      }
      // add more optional fields here
      return key;
    }

    @Override
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
          .apply(ParDo.of(new AlertSuppressor(alertSuppressionWindow)));
    }
  }
}
