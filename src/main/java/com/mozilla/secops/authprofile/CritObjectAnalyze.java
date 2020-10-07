package com.mozilla.secops.authprofile;

import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.authprofile.AuthProfile.AuthProfileOptions;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.Normalized;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Analysis for authentication involving critical objects
 *
 * <p>Analyze events to determine if they are related to any objects configured as being critical
 * objects. Where identified, generate critical level alerts.
 */
public class CritObjectAnalyze
    extends PTransform<PCollection<Event>, PCollection<KV<String, Alert>>>
    implements DocumentingTransform {
  private static final long serialVersionUID = 1L;

  private final String[] critObjects;
  private final String critNotifyEmail;
  private final String contactEmail;
  private final String docLink;
  private final String alternateCritSlackEscalation;
  private final boolean useEventTimestampForAlert;

  private DateTimeZone altEscalateTz;
  private int altEscalateHourStart;
  private int altEscalateHourStop;
  private String altEscalateChannel;

  private Logger log;
  private Pattern[] critObjectPat;

  /**
   * Initialize new critical object analysis
   *
   * @param options Pipeline options
   */
  public CritObjectAnalyze(AuthProfileOptions options) {
    critObjects = options.getCritObjects();
    critNotifyEmail = options.getCriticalNotificationEmail();
    contactEmail = options.getContactEmail();
    docLink = options.getDocLink();
    alternateCritSlackEscalation = options.getAlternateCritSlackEscalation();
    useEventTimestampForAlert = options.getUseEventTimestampForAlert();

    if (alternateCritSlackEscalation != null) {
      String[] parts = alternateCritSlackEscalation.split(":");
      if (parts.length != 4) {
        throw new IllegalArgumentException(
            "invalid format for alternate escalation policy, "
                + "must be <tz>:<start_hour>:<end_hour>:<channel_id>");
      }
      altEscalateTz = DateTimeZone.forID(parts[0]);
      if (altEscalateTz == null) {
        throw new IllegalArgumentException(
            "alternate escalation policy timezone lookup returned null");
      }
      altEscalateHourStart = Integer.parseInt(parts[1]);
      altEscalateHourStop = Integer.parseInt(parts[2]);
      altEscalateChannel = parts[3];
    }
    log = LoggerFactory.getLogger(CritObjectAnalyze.class);
    if (critObjects != null) {
      critObjectPat = new Pattern[critObjects.length];
      for (int i = 0; i < critObjects.length; i++) {
        critObjectPat[i] = Pattern.compile(critObjects[i]);
      }
    }
  }

  /** {@inheritDoc} */
  public String getTransformDoc() {
    return String.format(
        "Alert via %s immediately on auth events to specified objects: %s",
        critNotifyEmail, Arrays.toString(critObjects));
  }

  private void addEscalationMetadata(Alert a) {
    if (alternateCritSlackEscalation != null) {
      // We have an alternate escalation policy specified. Convert the alert timestamp
      // to match our policy timestamp, and see if it falls within the specified boundary.
      //
      // Note the policy is only applied if the resulting conversion falls on a weekday.
      //
      // ISO 6 (Saturday)
      // ISO 7 (Sunday)
      DateTime conv = a.getTimestamp().withZone(altEscalateTz);
      if ((conv.getHourOfDay() >= altEscalateHourStart
              && conv.getHourOfDay() <= altEscalateHourStop)
          && (conv.getDayOfWeek() != 6 && conv.getDayOfWeek() != 7)) {
        log.info("{}: using alternate escalation policy", a.getAlertId());
        // The alert matches the alternate policy; add the supplementary slack notification
        // details and just return.
        a.addMetadata(AlertMeta.Key.NOTIFY_SLACK_SUPPLEMENTARY, altEscalateChannel);
        a.addMetadata(
            AlertMeta.Key.SLACK_SUPPLEMENTARY_MESSAGE,
            String.format(
                "<!channel> critical authentication event observed %s to %s, %s [%s/%s]",
                a.getMetadataValue(AlertMeta.Key.USERNAME),
                a.getMetadataValue(AlertMeta.Key.OBJECT),
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY),
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY)));
        return;
      }
    }
    if (critNotifyEmail != null) {
      log.info(
          "{}: adding direct email notification metadata route for critical object alert to {}",
          a.getAlertId().toString(),
          critNotifyEmail);
      a.addMetadata(AlertMeta.Key.NOTIFY_EMAIL_DIRECT, critNotifyEmail);
    }
  }

  private void buildAlertSummary(Event e, Alert a) {
    String summary =
        String.format(
            "critical authentication event observed %s to %s, ",
            e.getNormalized().getSubjectUser(), e.getNormalized().getObject());
    summary =
        summary
            + String.format(
                "%s [%s/%s]",
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY),
                a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
    a.setSummary(summary);
  }

  private void buildAlertPayload(Event e, Alert a) {
    String msg =
        "An authentication event for user %s was detected to access %s from %s [%s/%s]. "
            + "This destination object is configured as a critical resource for which alerts are always"
            + " generated.";
    String payload =
        String.format(
            msg,
            a.getMetadataValue(AlertMeta.Key.USERNAME),
            a.getMetadataValue(AlertMeta.Key.OBJECT),
            a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
            a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY),
            a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));
    a.addToPayload(payload);
  }

  @Override
  public PCollection<KV<String, Alert>> expand(PCollection<Event> input) {
    PCollectionList<KV<String, Alert>> resultsList = PCollectionList.empty(input.getPipeline());

    resultsList =
        resultsList.and(
            input.apply(
                "critical object analysis for normalized objects",
                ParDo.of(
                    new DoFn<Event, KV<String, Alert>>() {
                      private static final long serialVersionUID = 1L;

                      @ProcessElement
                      public void processElement(ProcessContext c) {
                        if (critObjectPat == null) {
                          return;
                        }

                        Event e = c.element();
                        Normalized n = e.getNormalized();

                        String o = n.getObject();
                        if (o == null) {
                          return;
                        }

                        String matchobj = null;
                        for (Pattern p : critObjectPat) {
                          if (p.matcher(o).matches()) {
                            matchobj = o;
                          }
                        }
                        if (matchobj == null) {
                          return;
                        }

                        log.info(
                            "escalating critical object alert for {} {}",
                            e.getNormalized().getSubjectUser(),
                            e.getNormalized().getObject());
                        Alert a = AuthProfile.createBaseAlert(e, contactEmail, docLink);
                        a.setSubcategory("critical_object_analyze");
                        a.setSeverity(Alert.AlertSeverity.CRITICAL);
                        buildAlertSummary(e, a);
                        buildAlertPayload(e, a);
                        if (useEventTimestampForAlert) {
                          a.setTimestamp(e.getTimestamp());
                        }
                        addEscalationMetadata(a);
                        c.output(KV.of(e.getNormalized().getSubjectUser(), a));
                      }
                    })));

    return resultsList.apply("flatten critical alerts", Flatten.<KV<String, Alert>>pCollections());
  }
}
