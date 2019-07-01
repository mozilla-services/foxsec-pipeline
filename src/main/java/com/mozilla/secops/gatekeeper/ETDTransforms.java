package com.mozilla.secops.gatekeeper;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.*;
import com.mozilla.secops.parser.models.etd.EventThreatDetectionFinding;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.*;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;

public class ETDTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Extract ETD Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<Pattern> exclude;

    // static initializer for filter
    public ExtractFindings(String[] excludeRulePatterns) {
      if (excludeRulePatterns == null) {
        return;
      }
      if (excludeRulePatterns.length > 0) {
        exclude = new ArrayList<Pattern>();
      }
      for (String s : excludeRulePatterns) {
        exclude.add(Pattern.compile(s));
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
                  ETDBeta etdb;
                  try {
                    etdb = e.getPayload();
                  } catch (ClassCastException exc) {
                    return;
                  }
                  if (etdb != null) {
                    EventThreatDetectionFinding f = etdb.getFinding();
                    if ((f != null)
                        && (f.getDetectionCategory() != null)
                        && (f.getDetectionCategory().getRuleName() != null)) {
                      if (exclude != null) {
                        for (Pattern p : exclude) {
                          if (p.matcher(f.getDetectionCategory().getRuleName()).matches()) {
                            return;
                          }
                        }
                      }
                      c.output(e);
                    }
                  }
                }
              }));
    }
  }

  /** Generate Alerts for relevant ETD Finding Events */
  public static class GenerateAlerts extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:gcp";

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, com.mozilla.secops.alert.Alert>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  ETDBeta etdb = c.element().getPayload();
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
                          "Suspicious activity detected in GCP org %s project %s",
                          f.getSourceId().getCustomerOrganizationNumber(),
                          f.getProperties().getProject_id()));
                  a.setTimestamp(DateTime.parse(f.getEventTime()));
                  a.setCategory(alertCategory);
                  if (f.getProperties().getLocation() != null) {
                    a.addMetadata("location", f.getProperties().getLocation());
                  }
                  a.addMetadata("indicator", f.getDetectionCategory().getIndicator());
                  a.addMetadata("ruleName", f.getDetectionCategory().getRuleName());
                  a.addMetadata("technique", f.getDetectionCategory().getTechnique());
                  a.addMetadata("project number", f.getSourceId().getProjectNumber());
                  c.output(a);
                }
              }));
    }
  }
}
