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

public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Extract GuardDuty Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<Pattern> exclude;

    // static initializer for filter
    public ExtractFindings(String[] excludeTypePatterns) {
      if (excludeTypePatterns == null) {
        return;
      }
      if (excludeTypePatterns.length > 0) {
        exclude = new ArrayList<Pattern>();
      }
      for (String s : excludeTypePatterns) {
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
                  GuardDuty gde;
                  try {
                    gde = e.getPayload();
                  } catch (ClassCastException exc) {
                    return;
                  }
                  if (gde != null) {
                    Finding f = gde.getFinding();
                    if ((f != null) && (f.getType() != null)) {
                      if (exclude != null) {
                        for (Pattern p : exclude) {
                          if (p.matcher(f.getType()).matches()) {
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
                  GuardDuty gd = c.element().getPayload();
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
                          "Suspicious activity detected in AWS account %s: %s",
                          f.getAccountId(), f.getTitle()));
                  a.setTimestamp(DateTime.parse(f.getUpdatedAt()));
                  a.setCategory(alertCategory);
                  a.addMetadata("aws account", f.getAccountId());
                  a.addMetadata("aws region", f.getRegion());
                  a.addMetadata("description", f.getDescription());
                  a.addMetadata("finding aws severity", Double.toString(f.getSeverity()));
                  a.addMetadata("finding type", f.getType());
                  a.addMetadata("finding id", f.getId());
                  c.output(a);
                }
              }));
    }
  }
}
