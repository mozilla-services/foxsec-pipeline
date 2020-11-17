package com.mozilla.secops.authprofile;

import com.amazonaws.arn.Arn;
import com.mozilla.secops.authprofile.AuthProfile.AuthProfileOptions;
import com.mozilla.secops.parser.Cloudtrail;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilterPayload.StringProperty;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.Payload.PayloadType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterPane;
import org.apache.beam.sdk.transforms.windowing.AfterWatermark;
import org.apache.beam.sdk.transforms.windowing.Sessions;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Analyze cross account assumeRole events and correlates between the trusting account (the account
 * a role is being assumed in) and the trusted account (the account with the iam user assuming a
 * role).
 *
 * <p>The normalized event for the trusting account is fixed up with the user information from the
 * trusted event.
 */
public class AwsAssumeRoleCorrelator extends PTransform<PCollection<Event>, PCollection<Event>> {
  private static final long serialVersionUID = 1L;
  private Logger log;

  private Long sessionGapDuration;

  public AwsAssumeRoleCorrelator(AuthProfileOptions options) {
    log = LoggerFactory.getLogger(AwsAssumeRoleCorrelator.class);
    sessionGapDuration = options.getAwsAssumeRoleCorrelatorSessionGapDurationSeconds();
  }

  @Override
  public PCollection<Event> expand(PCollection<Event> input) {
    return input
        .apply("filter assume role events", ParDo.of(new CrossAccountAssumeRoleFilter()))
        .apply(
            Window.<KV<String, Event>>into(
                    Sessions.withGapDuration(Duration.standardSeconds(sessionGapDuration)))
                .triggering(
                    AfterWatermark.pastEndOfWindow()
                        .withEarlyFirings(AfterPane.elementCountAtLeast(2)))
                .withAllowedLateness(Duration.standardSeconds(0))
                .accumulatingFiredPanes())
        .apply(GroupByKey.<String, Event>create())
        .apply(ParDo.of(new FixUpNormalized()));
  }

  private static String extractCloudTrailEventID(Event e) {
    String account = e.getNormalized().getObject();
    if (e.getPayloadType().equals(PayloadType.CLOUDTRAIL)) {
      Cloudtrail ct = e.getPayload();
      String eventID = ct.getEventID();
      if (eventID != null) {
        // use account_cloudtrailEventID as deduplicaton key
        return String.format("%s_%s", account, eventID);
      }
    }
    return "";
  }

  /**
   * Creates an auth event using the assume role events from both the trusted and trusting account
   * that allows us to analyze which user was accessing the trusting account
   */
  private class FixUpNormalized extends DoFn<KV<String, Iterable<Event>>, Event> {

    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      String key = c.element().getKey();
      ArrayList<Event> events = new ArrayList<>();
      // deduplicate based on cloudtrail event ID
      Map<String, Boolean> processedEvents = new HashMap<>();
      c.element()
          .getValue()
          .forEach(
              e -> {
                String id = extractCloudTrailEventID(e);
                if (!processedEvents.containsKey(id)) {
                  events.add(e);
                  processedEvents.put(id, true);
                }
              });

      // if we have only one event and this is the last pane
      // we are missing the other event, log this for now
      // but we may want to output it so we can determine
      // if we are missing the source event for any critical objects
      if (events.size() == 1 && c.pane().isLast()) {
        log.info("Found only one event for sharedEventID {}", key);
        return;
      }
      if (events.size() != 2) {
        log.info("Received {} events for sharedEventID {}", events.size(), key);
        return;
      }

      // The event from the trusted account cannot be tagged as needing fix up
      // plus we validate the resource being accessed is in another account
      Event trustedAccountEvent =
          events
              .stream()
              .filter(
                  e ->
                      !e.getNormalized()
                          .hasStatusTag(Normalized.StatusTag.REQUIRES_SUBJECT_USER_FIXUP))
              .filter(e -> accessesRoleInDifferentAccount(e))
              .findAny()
              .orElse(null);
      // The event from the trusting account should be tagged as needing fix up
      Event trustingAccountEvent =
          events
              .stream()
              .filter(
                  e ->
                      e.getNormalized()
                          .hasStatusTag(Normalized.StatusTag.REQUIRES_SUBJECT_USER_FIXUP))
              .findAny()
              .orElse(null);

      if (trustedAccountEvent == null || trustingAccountEvent == null) {
        log.error("Cannot determine trusted and trusting accounts for sharedEventID {}", key);
        return;
      }

      // set the normalized subject user to be the user determined by the event from the trusted
      // account
      Normalized n = trustingAccountEvent.getNormalized();
      n.setSubjectUser(trustedAccountEvent.getNormalized().getSubjectUser());
      n.setSubjectUserIdentity(trustedAccountEvent.getNormalized().getSubjectUserIdentity());
      n.addStatusTag(Normalized.StatusTag.SUBJECT_USER_HAS_BEEN_FIXED);
      c.output(trustingAccountEvent);
    }

    /**
     * Checks if an event is requesting a role that does not match the recipientAccountID
     *
     * @param e
     * @return
     */
    private boolean accessesRoleInDifferentAccount(Event e) {
      Cloudtrail ct = e.getPayload();
      String roleArn = ct.getResource("requestParameters.roleArn");
      String recipientAccountID = ct.eventStringValue(StringProperty.CLOUDTRAIL_ACCOUNTID);

      if (roleArn == null) {
        return false;
      }
      try {
        Arn arn = Arn.fromString(roleArn);
        String roleAccountID = arn.getAccountId();
        return (roleAccountID != null
            && recipientAccountID != null
            && !roleAccountID.equals(recipientAccountID));
      } catch (IllegalArgumentException ex) {
        return false;
      }
    }
  }

  /**
   * Returns only AssumeRole events with a sharedEventID indicating there's events across two
   * accounts that need to be correlated
   */
  public static class CrossAccountAssumeRoleFilter extends DoFn<Event, KV<String, Event>> {
    private static final long serialVersionUID = 1L;

    @ProcessElement
    public void processElement(ProcessContext c) {
      Event e = c.element();

      if (e.getPayloadType().equals(PayloadType.CLOUDTRAIL)) {
        Cloudtrail ct = e.getPayload();
        if (ct.eventStringValue(StringProperty.CLOUDTRAIL_EVENTNAME).equals("AssumeRole")
            && ct.getSharedEventID() != null) {
          c.output(KV.of(ct.getSharedEventID(), e));
        }
      }
    }
  }
}
