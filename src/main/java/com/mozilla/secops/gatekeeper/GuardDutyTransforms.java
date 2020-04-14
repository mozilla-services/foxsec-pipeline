package com.mozilla.secops.gatekeeper;

import com.amazonaws.services.guardduty.model.Finding;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressor;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.GuardDuty;
import com.mozilla.secops.parser.Payload;
import java.io.IOException;
import java.io.Serializable;
import java.util.List;
import java.util.Map;
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

/** Implements various transforms on AWS GuardDuty {@link Finding} Events */
public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for GuardDuty Transforms */
  public interface Options extends PipelineOptions, IOOptions {
    @Description("Specify guardduty configuration location; resource path, gcs path")
    String getGuarddutyConfigPath();

    void setGuarddutyConfigPath(String value);

    @Default.Long(60 * 15) // 15 minutes
    @Description("Suppress alert generation for repeated GuardDuty Findings within this value")
    Long getAlertSuppressionSeconds();

    void setAlertSuppressionSeconds(Long value);
  }

  /** Extract GuardDuty Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<GuardDutyFindingMatcher> ignoreMatchers;

    /**
     * static initializer for filter
     *
     * @param opts {@link Options} pipeline options
     */
    public ExtractFindings(Options opts) {
      try {
        GuardDutyConfig gdc = GuardDutyConfig.load(opts.getGuarddutyConfigPath());
        ignoreMatchers = gdc.getIgnoreMatchers();
      } catch (IOException exc) {
        throw new RuntimeException(exc.getMessage());
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
                  if (f == null) {
                    return;
                  }
                  for (GuardDutyFindingMatcher matcher : ignoreMatchers) {
                    if (matcher.matches(f)) {
                      return;
                    }
                  }
                  c.output(e);
                }
              }));
    }
  }

  /** Generate Alerts for relevant Findings */
  public static class GenerateGDAlerts extends PTransform<PCollection<Event>, PCollection<Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:aws";

    private List<GuardDutyFindingMatcher> highMatchers;
    private final String critNotifyEmail;
    private final String identityMgrPath;

    private Logger log;

    /**
     * static initializer for alert generation / escalation
     *
     * @param opts {@link Options} pipeline options
     */
    public GenerateGDAlerts(Options opts) {
      log = LoggerFactory.getLogger(GenerateGDAlerts.class);

      critNotifyEmail = opts.getCriticalNotificationEmail();
      identityMgrPath = opts.getIdentityManagerPath();
      try {
        GuardDutyConfig gdc = GuardDutyConfig.load(opts.getGuarddutyConfigPath());
        highMatchers = gdc.getHighSeverityMatchers();
      } catch (IOException exc) {
        throw new RuntimeException(exc.getMessage());
      }
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return "Alerts are generated based on events sent from AWS's Guardduty.";
    }

    private String createFindingUrl(Finding f) {
      if (f.getRegion() == null || f.getId() == null) {
        return null;
      }
      return String.format(
          "https://%s.console.aws.amazon.com/guardduty/home?region=%s#/findings?fId=%s",
          f.getRegion(), f.getRegion(), f.getId());
    }

    private void addBaseFindingData(Alert a, Finding f, Map<String, String> awsAcctMap)
        throws IOException {
      if (f.getId() == null) {
        throw new IOException("guardduty alert was missing finding id");
      }
      a.addMetadata(AlertMeta.Key.FINDING_ID, f.getId());

      String acctId = f.getAccountId();
      if (acctId == null) {
        throw new IOException("guardduty alert was missing account id");
      }
      a.addMetadata(AlertMeta.Key.AWS_ACCOUNT_ID, acctId);

      if (f.getType() != null) {
        a.addMetadata(AlertMeta.Key.FINDING_TYPE, f.getType());
      }

      String acctName = null;
      if (awsAcctMap != null) {
        acctName = awsAcctMap.get(acctId);
        if (acctName != null) {
          a.addMetadata(AlertMeta.Key.AWS_ACCOUNT_NAME, acctName);
        }
      }

      if (f.getRegion() != null) {
        a.addMetadata(AlertMeta.Key.AWS_REGION, f.getRegion());

        // If we have the region, we can also create a link to the finding
        a.addMetadata(
            AlertMeta.Key.URL_TO_FINDING,
            String.format(
                "https://%s.console.aws.amazon.com/guardduty/home?region=%s#/findings?fId=%s",
                f.getRegion(), f.getRegion(), f.getId()));
      }
      if (f.getDescription() != null) {
        a.addMetadata(AlertMeta.Key.DESCRIPTION, f.getDescription());
      }

      a.setSummary(
          String.format(
              "suspicious activity detected in aws account %s: %s",
              acctName != null ? acctName : acctId,
              f.getTitle() != null ? f.getTitle() : "unknown"));

      a.setCategory(alertCategory);
      a.setSeverity(Alert.AlertSeverity.CRITICAL);
    }

    private void addFindingSeverity(Alert a, Finding f) {
      for (GuardDutyFindingMatcher matcher : highMatchers) {
        if (matcher.matches(f)) {
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

                private Map<String, String> awsAcctMap;

                @Setup
                public void setup() {
                  if (identityMgrPath != null) {
                    try {
                      awsAcctMap = IdentityManager.load(identityMgrPath).getAwsAccountMap();
                    } catch (IOException x) {
                      log.error(
                          "failed to load identity manager, alerts will not contain aws_account_name. error: {}",
                          x.getMessage());
                    }
                  }
                }

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

                  try {
                    addBaseFindingData(a, f, awsAcctMap);
                  } catch (IOException exc) {
                    log.error("error processing guardduty alert: {}", exc.getMessage());
                    return;
                  }
                  addFindingSeverity(a, f);
                  c.output(a);
                }
              }));
    }
  }

  /**
   * Suppress Alerts for repeated GuardDuty Findings.
   *
   * <p>A "repeated finding" in GuardDuty means the same (potential) bad actor is performing the
   * same action against the same resource in your AWS environment. Findings are uniquely identified
   * by their "id".
   *
   * <p>GuardDuty has a built-in setting to avoid emitting a new CloudWatch event for repeated
   * findings within a certain window of time. Valid values for that window are 15 minutes, 1 hour,
   * or 6 hours (default).
   * https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html#guardduty_findings_cloudwatch_notification_frequency
   *
   * <p>This transform adds a second layer of protection against generation of alerts for repeated
   * findings
   */
  public static class SuppressAlerts extends PTransform<PCollection<Alert>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;
    private static final AlertMeta.Key suppressionStateMetadataKey = AlertMeta.Key.FINDING_ID;

    private static Long alertSuppressionWindow;

    /**
     * static initializer for alert suppression
     *
     * @param opts {@link Options} pipeline options
     */
    public SuppressAlerts(Options opts) {
      alertSuppressionWindow = opts.getAlertSuppressionSeconds();
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
                      if (a == null || a.getMetadataValue(suppressionStateMetadataKey) == null) {
                        return;
                      }
                      c.output(KV.of(a.getMetadataValue(suppressionStateMetadataKey), a));
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
