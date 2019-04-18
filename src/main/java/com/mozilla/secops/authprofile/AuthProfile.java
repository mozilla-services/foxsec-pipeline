package com.mozilla.secops.authprofile;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.CompositeInput;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.identity.Identity;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link AuthProfile} implements analysis of normalized authentication events
 *
 * <p>This pipeline can make use of various methods for persistent state storage.
 */
public class AuthProfile implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Parse input strings returning applicable authentication events.
   *
   * <p>Events which are not of type {@link com.mozilla.secops.parser.Normalized.Type#AUTH} or
   * {@link com.mozilla.secops.parser.Normalized.Type#AUTH_SESSION} are not returned in the
   * resulting {@link PCollection}.
   *
   * <p>This transform also filters events associated with ignored or inapplicable users from the
   * result set.
   */
  public static class Parse extends PTransform<PCollection<String>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private Logger log;
    private final String[] ignoreUserRegex;
    private final String[] autoignoreUsers;
    private final ParserCfg cfg;

    /**
     * Static initializer for {@link Parse} using specified pipeline options
     *
     * @param options Pipeline options
     */
    public Parse(AuthProfileOptions options) {
      log = LoggerFactory.getLogger(Parse.class);
      ignoreUserRegex = options.getIgnoreUserRegex();
      autoignoreUsers =
          new String[] {
            "cluster-autoscaler",
            "system:unsecured",
            "system:serviceaccount:kube-system:endpoint-controller",
            "system:kube-proxy"
          };
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();

      // We are interested in both AUTH here (which indicates an authentication activity) and
      // in AUTH_SESSION (which indicates on-going use of an already authenticated session)
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH));
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH_SESSION));

      return col.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)))
          .apply(
              ParDo.of(
                  new DoFn<Event, Event>() {
                    private static final long serialVersionUID = 1L;

                    private Pattern[] ignoreUsers;

                    @Setup
                    public void setup() throws IOException {
                      if (ignoreUserRegex != null) {
                        ignoreUsers = new Pattern[ignoreUserRegex.length];
                        for (int i = 0; i < ignoreUserRegex.length; i++) {
                          ignoreUsers[i] = Pattern.compile(ignoreUserRegex[i]);
                        }
                      }
                    }

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Event e = c.element();
                      Normalized n = e.getNormalized();

                      if (n.getSubjectUser() == null || n.getSourceAddress() == null) {
                        // At a minimum we want a subject user and a source address here
                        return;
                      }

                      // Filter any auto-ignored users
                      for (String i : autoignoreUsers) {
                        if (i.equals(n.getSubjectUser())) {
                          return;
                        }
                      }

                      if (ignoreUsers != null) {
                        for (Pattern p : ignoreUsers) {
                          if (p.matcher(n.getSubjectUser()).matches()) {
                            log.info("{}: ignoring event for ignored user", n.getSubjectUser());
                            return;
                          }
                        }
                      }

                      // Ignore events with an ip6 loopback as is seen with some GCP audit calls
                      if (n.getSourceAddress().equals("0:0:0:0:0:0:0:1")) {
                        return;
                      }

                      c.output(e);
                    }
                  }));
    }
  }

  /**
   * Extract subject user for each event in input {@link PCollection}
   *
   * <p>For each event in the input collection, extract the subject user and attempt to map the
   * username to a known identity. If found, a {@link KV} is emitted with the key being the identity
   * and the value being the original event.
   *
   * <p>If an identity is not found for the subject user, the key will simply be the subject user.
   * However if pipeline options have been configured to ignore unknown identities, these elements
   * will be dropped.
   */
  public static class ExtractIdentity extends DoFn<Event, KV<String, Event>> {
    private static final long serialVersionUID = 1L;

    private final String idmanagerPath;
    private final Boolean ignoreUnknownIdentities;
    private IdentityManager idmanager;
    private Logger log;

    /**
     * Static initializer for {@link ExtractIdentity}
     *
     * @param options Pipeline options
     */
    public ExtractIdentity(AuthProfileOptions options) {
      idmanagerPath = options.getIdentityManagerPath();
      ignoreUnknownIdentities = options.getIgnoreUnknownIdentities();
    }

    @Setup
    public void setup() throws IOException {
      log = LoggerFactory.getLogger(ExtractIdentity.class);
      idmanager = IdentityManager.load(idmanagerPath);
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      Event e = c.element();
      Normalized n = e.getNormalized();

      String identityKey = idmanager.lookupAlias(n.getSubjectUser());
      if (identityKey != null) {
        log.info("{}: resolved identity to {}", n.getSubjectUser(), identityKey);
        c.output(KV.of(identityKey, e));
      } else {
        if (ignoreUnknownIdentities) {
          log.info("{}: ignoring event as identity is unknown", n.getSubjectUser());
        } else {
          log.info(
              "{}: identity is unknown, publishing event keyed with subject user",
              n.getSubjectUser());
          c.output(KV.of(n.getSubjectUser(), e));
        }
      }
    }
  }

  /**
   * Analysis for authentication involving critical objects
   *
   * <p>Analyze events to determine if they are related to any objects configured as being critical
   * objects. Where identified, generate critical level alerts.
   */
  public static class CritObjectAnalyze extends DoFn<Event, Alert> {
    private static final long serialVersionUID = 1L;

    private final String[] critObjects;
    private final String critNotifyEmail;

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
    }

    @Setup
    public void setup() {
      log = LoggerFactory.getLogger(StateAnalyze.class);
      if (critObjects != null) {
        critObjectPat = new Pattern[critObjects.length];
        for (int i = 0; i < critObjects.length; i++) {
          critObjectPat[i] = Pattern.compile(critObjects[i]);
        }
      }
    }

    private void addEscalationMetadata(Alert a) {
      if (critNotifyEmail != null) {
        log.info(
            "{}: adding direct email notification metadata route for critical object alert to {}",
            a.getAlertId().toString(),
            critNotifyEmail);
        a.addMetadata("notify_email_direct", critNotifyEmail);
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
                  a.getMetadataValue("sourceaddress"),
                  a.getMetadataValue("sourceaddress_city"),
                  a.getMetadataValue("sourceaddress_country"));
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
              a.getMetadataValue("username"),
              a.getMetadataValue("object"),
              a.getMetadataValue("sourceaddress"),
              a.getMetadataValue("sourceaddress_city"),
              a.getMetadataValue("sourceaddress_country"));
      a.addToPayload(payload);
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      if (critObjectPat == null) {
        return;
      }

      Event e = c.element();
      Normalized n = e.getNormalized();
      String o = n.getObject();

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
      Alert a = AuthProfile.createBaseAlert(e);
      a.addMetadata("category", "critical_object_analyze");
      a.setSeverity(Alert.AlertSeverity.CRITICAL);
      buildAlertSummary(e, a);
      buildAlertPayload(e, a);
      addEscalationMetadata(a);
      c.output(a);
    }
  }

  /**
   * Analyze grouped events associated with a particular user or identity against persistent user
   * state
   */
  public static class StateAnalyze extends DoFn<KV<String, Iterable<Event>>, Alert> {
    private static final long serialVersionUID = 1L;

    private final String memcachedHost;
    private final Integer memcachedPort;
    private final String datastoreNamespace;
    private final String datastoreKind;
    private final String idmanagerPath;
    private CidrUtil cidrGcp;
    private Map<String, String> namedSubnets;
    private IdentityManager idmanager;
    private Logger log;
    private State state;

    /**
     * Static initializer for {@link StateAnalyze} using specified pipeline options
     *
     * @param options Pipeline options for {@link AuthProfile}
     */
    public StateAnalyze(AuthProfileOptions options) {
      memcachedHost = options.getMemcachedHost();
      memcachedPort = options.getMemcachedPort();
      datastoreNamespace = options.getDatastoreNamespace();
      datastoreKind = options.getDatastoreKind();
      idmanagerPath = options.getIdentityManagerPath();
    }

    @Setup
    public void setup() throws StateException, IOException {
      log = LoggerFactory.getLogger(StateAnalyze.class);

      idmanager = IdentityManager.load(idmanagerPath);
      namedSubnets = idmanager.getNamedSubnets();

      cidrGcp = new CidrUtil();
      cidrGcp.loadGcpSubnets();

      if (memcachedHost != null && memcachedPort != null) {
        log.info("using memcached for state management");
        state = new State(new MemcachedStateInterface(memcachedHost, memcachedPort));
      } else if (datastoreNamespace != null && datastoreKind != null) {
        log.info("using datastore for state management");
        state = new State(new DatastoreStateInterface(datastoreKind, datastoreNamespace));
      } else {
        throw new IllegalArgumentException("could not find valid state parameters in options");
      }
      state.initialize();
    }

    @Teardown
    public void teardown() {
      state.done();
    }

    private String getEntryKey(String ipAddr) {
      if (namedSubnets == null) {
        return ipAddr;
      }
      for (Map.Entry<String, String> namedSubnet : namedSubnets.entrySet()) {
        if (CidrUtil.addressInCidr(ipAddr, namedSubnet.getValue())) {
          return namedSubnet.getKey();
        }
      }
      return ipAddr;
    }

    private Boolean ignoreDuplicateSourceAddress(Event e, ArrayList<String> list) {
      for (String s : list) {
        if (s.equals(e.getNormalized().getSourceAddress())) {
          return true;
        }
      }
      list.add(e.getNormalized().getSourceAddress());
      return false;
    }

    private void addEscalationMetadata(Alert a, Identity identity) {
      if (identity.getEscalateTo() != null) {
        a.addMetadata("escalate_to", identity.getEscalateTo());
      }

      String dnote = identity.getEmailNotifyDirect(idmanager.getDefaultNotification());
      if (dnote != null) {
        log.info(
            "{}: adding direct email notification metadata route to {}",
            a.getMetadataValue("identity_key"),
            dnote);
        a.addMetadata("notify_email_direct", dnote);
      }
      if (identity.getSlackNotifyDirect(idmanager.getDefaultNotification())) {
        log.info("{}: adding direct slack notification", a.getMetadataValue("identity_key"));
        a.addMetadata("notify_slack_direct", a.getMetadataValue("identity_key"));
        if (identity.getSlackConfirmationAlertFeatureFlag(idmanager.getDefaultFeatureFlags())) {
          a.addMetadata("alert_notification_type", "slack_confirmation");
          // This is used outside of dataflow to keep track of the users response.
          a.addMetadata("status", "NEW");
        } else {
          a.addMetadata("alert_notification_type", "slack_notification");
        }
      }
    }

    private void buildAlertSummary(Event e, Alert a) {
      String summary =
          String.format(
              "authentication event observed %s [%s] to %s, ",
              e.getNormalized().getSubjectUser(),
              a.getMetadataValue("identity_key") != null
                  ? a.getMetadataValue("identity_key")
                  : "untracked",
              e.getNormalized().getObject());
      if (a.getSeverity().equals(Alert.AlertSeverity.WARNING)) {
        summary = summary + "new source ";
      }
      summary =
          summary
              + String.format(
                  "%s [%s/%s]",
                  a.getMetadataValue("sourceaddress"),
                  a.getMetadataValue("sourceaddress_city"),
                  a.getMetadataValue("sourceaddress_country"));
      a.setSummary(summary);
    }

    private void buildAlertPayload(Event e, Alert a) {
      String msg = "An authentication event for user %s was detected to access %s from %s [%s/%s].";
      if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
        msg = "A sensitive event from user %s was detected in association with %s from %s [%s/%s].";
      }
      String payload =
          String.format(
              msg,
              a.getMetadataValue("username"),
              a.getMetadataValue("object"),
              a.getMetadataValue("sourceaddress"),
              a.getMetadataValue("sourceaddress_city"),
              a.getMetadataValue("sourceaddress_country"));
      if (a.getMetadataValue("identity_key") != null) {
        if (a.getSeverity().equals(Alert.AlertSeverity.WARNING)) {
          payload = payload + " This occurred from a source address unknown to the system.";
        } else {
          payload = payload + " This occurred from a known source address.";
        }
      } else {
        payload = payload + " This event occurred for an untracked identity.";
      }
      payload =
          payload
              + "\n\nIf this was not you, or you have any questions about "
              + "this alert, email us at secops@mozilla.com with the alert id.";
      a.addToPayload(payload);
    }

    @ProcessElement
    public void processElement(ProcessContext c) throws StateException {
      Iterable<Event> events = c.element().getValue();
      String userIdentity = c.element().getKey();
      Identity identity = idmanager.getIdentity(userIdentity);

      ArrayList<String> seenNewAddresses = new ArrayList<>();
      ArrayList<String> seenKnownAddresses = new ArrayList<>();

      for (Event e : events) {
        Alert a = AuthProfile.createBaseAlert(e);
        a.addMetadata("category", "state_analyze");

        if (cidrGcp.contains(e.getNormalized().getSourceAddress())) {
          // At some point we may want some special handling here, but for now just add an
          // additional metadata tag indicating the event had a GCP origin.
          a.addMetadata("gcp_origin", "true");
        }

        if (identity == null) {
          a.addMetadata("identity_untracked", "true");
          // New/known do not apply for untracked, but just use the new address ignore list here
          if (ignoreDuplicateSourceAddress(e, seenNewAddresses)) {
            continue;
          }
        } else {
          StateCursor cur = state.newCursor();

          a.addMetadata("identity_key", userIdentity);
          // The event was for a tracked identity, initialize the state model
          StateModel sm = StateModel.get(userIdentity, cur);
          if (sm == null) {
            sm = new StateModel(userIdentity);
          }

          String entryKey = getEntryKey(e.getNormalized().getSourceAddress());
          if (!entryKey.equals(e.getNormalized().getSourceAddress())) {
            a.addMetadata("entry_key", entryKey);
          }

          if (sm.updateEntry(entryKey)) {
            // Check new address ignore list
            if (ignoreDuplicateSourceAddress(e, seenNewAddresses)) {
              cur.commit();
              continue;
            }
            // Address was new
            log.info(
                "{}: escalating alert criteria for new source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
            a.setSeverity(Alert.AlertSeverity.WARNING);
            addEscalationMetadata(a, identity);
          } else {
            // Check known address ignore list
            if (ignoreDuplicateSourceAddress(e, seenKnownAddresses)) {
              cur.commit();
              continue;
            }

            // Address was known
            log.info(
                "{}: access from known source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
          }

          // Update persistent state with new information
          try {
            sm.set(cur);
          } catch (StateException exc) {
            log.error("{}: error updating state: {}", userIdentity, exc.getMessage());
          }
        }

        buildAlertSummary(e, a);
        buildAlertPayload(e, a);
        c.output(a);
      }
    }
  }

  /** Runtime options for {@link AuthProfile} pipeline. */
  public interface AuthProfileOptions extends PipelineOptions, InputOptions, OutputOptions {
    @Description("Enable state analysis")
    @Default.Boolean(true)
    Boolean getEnableStateAnalysis();

    void setEnableStateAnalysis(Boolean value);

    @Description("Enable critical object analysis")
    @Default.Boolean(true)
    Boolean getEnableCritObjectAnalysis();

    void setEnableCritObjectAnalysis(Boolean value);

    @Description("Use memcached state; hostname of memcached server")
    String getMemcachedHost();

    void setMemcachedHost(String value);

    @Description("Use memcached state; port of memcached server")
    @Default.Integer(11211)
    Integer getMemcachedPort();

    void setMemcachedPort(Integer value);

    @Description("Use Datastore state; namespace for entities")
    String getDatastoreNamespace();

    void setDatastoreNamespace(String value);

    @Description("Use Datastore state; kind for entities")
    String getDatastoreKind();

    void setDatastoreKind(String value);

    @Description("Ignore events for any usernames match regex (multiple allowed)")
    String[] getIgnoreUserRegex();

    void setIgnoreUserRegex(String[] value);

    @Description("If true, never create informational alerts for unknown identities")
    @Default.Boolean(false)
    Boolean getIgnoreUnknownIdentities();

    void setIgnoreUnknownIdentities(Boolean value);

    @Description("Objects to consider for critical object analysis; regex (multiple allowed)")
    String[] getCritObjects();

    void setCritObjects(String[] value);

    @Description("Email address to receive critical alert notifications")
    String getCriticalNotificationEmail();

    void setCriticalNotificationEmail(String value);
  }

  /**
   * Create a base authprofile {@link Alert} using information from the event
   *
   * @param e Event
   * @return Base alert object
   */
  public static Alert createBaseAlert(Event e) {
    Alert a = new Alert();

    Normalized n = e.getNormalized();
    a.addMetadata("object", n.getObject());
    a.addMetadata("username", n.getSubjectUser());
    a.addMetadata("sourceaddress", n.getSourceAddress());
    a.setCategory("authprofile");

    a.setEmailTemplateName("email/authprofile.ftlh");
    a.setSlackTemplateName("slack/authprofile.ftlh");

    String city = n.getSourceAddressCity();
    if (city != null) {
      a.addMetadata("sourceaddress_city", city);
    } else {
      a.addMetadata("sourceaddress_city", "unknown");
    }
    String country = n.getSourceAddressCountry();
    if (city != null) {
      a.addMetadata("sourceaddress_country", country);
    } else {
      a.addMetadata("sourceaddress_country", "unknown");
    }

    if (e.getNormalized().isOfType(Normalized.Type.AUTH)) {
      a.addMetadata("auth_alert_type", "auth");
    } else if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
      a.addMetadata("auth_alert_type", "auth_session");
    }

    DateTime eventTimestamp = e.getTimestamp();
    if (eventTimestamp != null) {
      a.addMetadata("event_timestamp", eventTimestamp.toString());
    }

    return a;
  }

  public static PCollection<Alert> processInput(
      PCollection<String> input, AuthProfileOptions options) {
    PCollectionList<Alert> alertList = PCollectionList.empty(input.getPipeline());

    PCollection<Event> events = input.apply("parse", new Parse(options));

    if (options.getEnableStateAnalysis()) {
      alertList =
          alertList.and(
              events
                  .apply("extract identity", ParDo.of(new ExtractIdentity(options)))
                  .apply("window for state analyze", new GlobalTriggers<KV<String, Event>>(60))
                  .apply("state analyze gbk", GroupByKey.<String, Event>create())
                  .apply("state analyze", ParDo.of(new StateAnalyze(options)))
                  .apply("state analyze rewindow for output", new GlobalTriggers<Alert>(5)));
    }

    if (options.getEnableCritObjectAnalysis()) {
      alertList =
          alertList.and(
              events
                  .apply("critical object analyze", ParDo.of(new CritObjectAnalyze(options)))
                  .apply(
                      "critical object analyze rewindow for output", new GlobalTriggers<Alert>(5)));
    }

    return alertList.apply("flatten output", Flatten.<Alert>pCollections());
  }

  private static void runAuthProfile(AuthProfileOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    PCollection<String> input = p.apply("input", new CompositeInput(options));
    processInput(input, options)
        .apply("output format", ParDo.of(new AlertFormatter(options)))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   */
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(AuthProfileOptions.class);
    AuthProfileOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(AuthProfileOptions.class);
    runAuthProfile(options);
  }
}
