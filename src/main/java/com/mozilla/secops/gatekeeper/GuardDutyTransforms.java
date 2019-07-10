package com.mozilla.secops.gatekeeper;

import com.amazonaws.services.guardduty.model.Finding;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.parser.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.*;
import org.apache.beam.sdk.values.*;
import org.joda.time.DateTime;

/** Implements various transforms on AWS GuardDuty {@link Finding} Events */
public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Extract GuardDuty Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<Pattern> exclude;

    /**
     * static initializer for filter
     *
     * @param excludeTypePatterns String[] of regexes to exclude from alert generation
     */
    public ExtractFindings(String[] excludeTypePatterns) {
      exclude = new ArrayList<Pattern>();
      if (excludeTypePatterns != null) {
        for (String s : excludeTypePatterns) {
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
                  if (!e.getPayloadType().equals(Payload.PayloadType.GUARDDUTY)) {
                    return;
                  }
                  GuardDuty gde = e.getPayload();
                  if (gde == null) {
                    return;
                  }
                  Finding f = gde.getFinding();
                  if (f == null || f.getType() == null) {
                    return;
                  }
                  for (Pattern p : exclude) {
                    if (p.matcher(f.getType()).matches()) {
                      return;
                    }
                  }
                  c.output(e);
                }
              }));
    }
  }

  /** Generate Alerts for relevant Findings */
  public static class GenerateAlerts extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:aws";

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, Alert>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  Event e = c.element();
                  if (!e.getPayloadType().equals(Payload.PayloadType.GUARDDUTY)) {
                    return;
                  }
                  GuardDuty gd = e.getPayload();
                  if (gd == null) {
                    return;
                  }
                  Finding f = gd.getFinding();
                  if (f == null) {
                    return;
                  }
                  Alert a = new Alert();
                  a.setSummary(
                      String.format(
                          "suspicious activity detected in aws account %s: %s",
                          f.getAccountId(), f.getTitle()));
                  a.setTimestamp(DateTime.parse(f.getUpdatedAt()));
                  a.setCategory(alertCategory);
                  a.setSeverity(Alert.AlertSeverity.CRITICAL);
                  a.addMetadata("aws_account", f.getAccountId());
                  a.addMetadata("aws_region", f.getRegion());
                  a.addMetadata("description", f.getDescription());
                  a.addMetadata("finding_aws_severity", Double.toString(f.getSeverity()));
                  a.addMetadata("finding_type", f.getType());
                  a.addMetadata("finding_id", f.getId());
                  c.output(a);
                }
              }));
    }
  }
}
