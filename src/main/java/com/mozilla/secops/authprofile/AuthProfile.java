package com.mozilla.secops.authprofile;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertIO;
import com.mozilla.secops.authstate.AuthStateModel;
import com.mozilla.secops.authstate.PruningStrategyEntryAge;
import com.mozilla.secops.identity.Identity;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.input.Input;
import com.mozilla.secops.metrics.CfgTickBuilder;
import com.mozilla.secops.metrics.CfgTickProcessor;
import com.mozilla.secops.parser.Auth0;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.parser.Payload;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import com.mozilla.secops.window.GlobalTriggers;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.joda.time.DateTimeZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link AuthProfile} implements analysis of normalized authentication events
 *
 * <p>This pipeline can make use of various methods for persistent state storage.
 */
public class AuthProfile implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final String EMAIL_TEMPLATE = "email/authprofile.ftlh";
  private static final String SLACK_TEMPLATE = "slack/authprofile.ftlh";
  private static final String[] ALERT_TEMPLATES = new String[] {EMAIL_TEMPLATE, SLACK_TEMPLATE};

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
    private final String[] auth0ClientIds;
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
          new String[] {"cluster-autoscaler", "system:unsecured", "system:kube-proxy"};
      auth0ClientIds = options.getAuth0ClientIds();
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<Event> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter().passConfigurationTicks();

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

                      if (e.getPayloadType().equals(Payload.PayloadType.CFGTICK)) {
                        c.output(e);
                        return;
                      }

                      // Filter out all auth0 auth events we don't explicitly want to monitor.
                      if (e.getPayloadType().equals(Payload.PayloadType.AUTH0)) {
                        Auth0 a = e.getPayload();
                        if (!a.hasClientIdIn(auth0ClientIds)) {
                          return;
                        }
                      }

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

                      if ((e.getPayloadType().equals(Payload.PayloadType.CLOUDTRAIL))
                          && (n.getSourceAddress().equals("AWS Internal"))) {
                        log.info("ignoring event with AWS Internal source address");
                        return;
                      }

                      if (e.getPayloadType().equals(Payload.PayloadType.GCPAUDIT)) {
                        // Some GCP audit events can be generated with an internal IP in the
                        // source address field, even though the actual event may have been
                        // initiated from a valid routable IPv4 address.
                        //
                        // Identify these here and filter them out.
                        if (n.getSourceAddress().equals("0:0:0:0:0:0:0:1")
                            || n.getSourceAddress().equals("0.1.0.1")) {
                          log.info(
                              "{}: ignoring gcp audit event from internal source {}",
                              n.getSubjectUser(),
                              n.getSourceAddress());
                          return;
                        }

                        // Auto-ignore GCP audit records for accounts prefixed with
                        // system:serviceaccount:
                        if (n.getSubjectUser().startsWith("system:serviceaccount:")) {
                          log.info(
                              "{}: ignoring GCP system service account entry", n.getSubjectUser());
                          return;
                        }
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

      if (n.getSubjectUser() == null) {
        return;
      }

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
  public static class CritObjectAnalyze extends DoFn<Event, Alert> implements DocumentingTransform {
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

    public String getTransformDoc() {
      return String.format(
          "Alert via %s immediately on auth events to specified objects: %s",
          critNotifyEmail, Arrays.toString(critObjects));
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
  public static class StateAnalyze extends DoFn<KV<String, Iterable<Event>>, Alert>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final String memcachedHost;
    private final Integer memcachedPort;
    private final String datastoreNamespace;
    private final String datastoreKind;
    private final String idmanagerPath;
    private final Double maxKilometersPerSecond;
    private CidrUtil cidrGcp;
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
      maxKilometersPerSecond = options.getMaximumKilometersPerHour() / 3600.0;
    }

    public String getTransformDoc() {
      return "Alert if an identity (can be thought of as a user) authenticates from a new IP";
    }

    @Setup
    public void setup() throws StateException, IOException {
      log = LoggerFactory.getLogger(StateAnalyze.class);

      idmanager = IdentityManager.load(idmanagerPath);

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
      String ret = idmanager.lookupNamedSubnet(ipAddr);
      if (ret != null) {
        return ret;
      }
      return ipAddr;
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
        } else {
          a.addMetadata("alert_notification_type", "slack_notification");
        }
      }
    }

    private void buildGeoVelocityAlertSummary(Event e, Alert a) {
      String summary =
          String.format(
              "geovelocity anomaly detected on authentication event by %s [%s] to %s, ",
              e.getNormalized().getSubjectUser(),
              a.getMetadataValue("identity_key") != null
                  ? a.getMetadataValue("identity_key")
                  : "untracked",
              e.getNormalized().getObject());
      summary =
          summary
              + String.format(
                  "%s [%s/%s]",
                  a.getMetadataValue("sourceaddress"),
                  a.getMetadataValue("sourceaddress_city"),
                  a.getMetadataValue("sourceaddress_country"));
      a.setSummary(summary);
    }

    private void buildGeoVelocityAlertPayload(Event e, Alert a) {
      String msg =
          "Geovelocity anomaly detected on an authentication event for user %s accessing %s from %s [%s/%s].";
      if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
        msg =
            "Geovelocity anomaly detected on a sensitive event for user %s in association with %s from %s [%s/%s].";
      }
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

      ArrayList<String> seenKnownAddresses = new ArrayList<>();

      for (Event e : events) {
        Alert a = AuthProfile.createBaseAlert(e);
        a.addMetadata("category", "state_analyze");

        // If the address is already in the known address list, we have already processed it
        // as known so just skip the state logic
        boolean isSeen = false;
        for (String s : seenKnownAddresses) {
          if (s.equals(e.getNormalized().getSourceAddress())) {
            isSeen = true;
            break;
          }
        }
        if (isSeen) {
          continue;
        }

        if ((e.getPayloadType().equals(Payload.PayloadType.GCPAUDIT))
            && ((cidrGcp.contains(e.getNormalized().getSourceAddress()))
                || (CidrUtil.resolvedCanonicalHostMatches(
                    e.getNormalized().getSourceAddress(), ".*\\.google\\.com$")))) {
          // Skip AlertIO if it's a GCP event from GCP source, we can also skip the remainder of the
          // logic here
          a.addMetadata(AlertIO.ALERTIO_IGNORE_EVENT, "true");
          buildAlertSummary(e, a);
          buildAlertPayload(e, a);
          c.output(a);
          continue;
        }

        if (identity == null) {
          a.addMetadata("identity_untracked", "true");
          // We do not keep state for untracked identities, but just use the known address
          // list here to filter any duplicates that are part of this batch
          seenKnownAddresses.add(e.getNormalized().getSourceAddress());
          // We also want to skip AlertIO for untracked identities here
          a.addMetadata(AlertIO.ALERTIO_IGNORE_EVENT, "true");
        } else {
          StateCursor cur = state.newCursor();

          a.addMetadata("identity_key", userIdentity);
          // The event was for a tracked identity, initialize the state model
          AuthStateModel sm = AuthStateModel.get(userIdentity, cur, new PruningStrategyEntryAge());
          if (sm == null) {
            sm = new AuthStateModel(userIdentity);
          }

          String entryKey = getEntryKey(e.getNormalized().getSourceAddress());
          if (!entryKey.equals(e.getNormalized().getSourceAddress())) {
            a.addMetadata("entry_key", entryKey);
          }

          if (sm.updateEntry(
              entryKey,
              e.getNormalized().getSourceAddressLatitude(),
              e.getNormalized().getSourceAddressLongitude())) {

            // Address was new
            log.info(
                "{}: escalating alert criteria for new source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
            a.setSeverity(Alert.AlertSeverity.WARNING);
            addEscalationMetadata(a, identity);

            AuthStateModel.GeoVelocityResponse geoResp =
                sm.geoVelocityAnalyzeLatest(maxKilometersPerSecond);

            if (geoResp != null) {
              log.info(
                  "{}: new location is {}km away from last location within {}s",
                  userIdentity,
                  geoResp.getKmDistance(),
                  geoResp.getTimeDifference());
              if (geoResp.getMaxKmPerSecondExceeded()) {
                log.info("{}: creating geo velocity alert", userIdentity);
                Alert ga = AuthProfile.createBaseAlert(e);
                ga.addMetadata("identity_key", userIdentity);
                ga.addMetadata("category", "geo_velocity");
                // TODO: Once this has run for a while, should switch to CRITICAL and add escalation
                // metadata
                ga.setSeverity(Alert.AlertSeverity.INFORMATIONAL);
                buildGeoVelocityAlertSummary(e, ga);
                buildGeoVelocityAlertPayload(e, ga);
                c.output(ga);
              }
            }

          } else {
            seenKnownAddresses.add(e.getNormalized().getSourceAddress());

            // Address was known
            log.info(
                "{}: access from known source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
          }

          // Update persistent state with new information
          try {
            sm.set(cur, new PruningStrategyEntryAge());
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
  public interface AuthProfileOptions extends PipelineOptions, IOOptions {
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

    @Description("Maxmimum km/hr for location velocity analysis")
    @Default.Integer(800)
    Integer getMaximumKilometersPerHour();

    void setMaximumKilometersPerHour(Integer value);

    @Description("Auth0 Client ids to consider for state analysis (multiple allowed)")
    String[] getAuth0ClientIds();

    void setAuth0ClientIds(String[] value);
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

    a.setEmailTemplate(EMAIL_TEMPLATE);
    a.setSlackTemplate(SLACK_TEMPLATE);

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
    String tz = n.getSourceAddressTimeZone();
    if (tz != null) {
      a.addMetadata("sourceaddress_timezone", tz);
    } else {
      a.addMetadata("sourceaddress_timezone", "unknown");
    }

    if (e.getNormalized().isOfType(Normalized.Type.AUTH)) {
      a.addMetadata("auth_alert_type", "auth");
    } else if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
      a.addMetadata("auth_alert_type", "auth_session");
    }

    DateTime eventTimestamp = e.getTimestamp();
    if (eventTimestamp != null) {
      a.addMetadata("event_timestamp", eventTimestamp.toString());

      if (tz != null) {
        DateTimeZone dtz = DateTimeZone.forID(tz);
        if (dtz != null) {
          a.addMetadata("event_timestamp_source_local", eventTimestamp.withZone(dtz).toString());
        }
      }
    }

    return a;
  }

  /**
   * Build a configuration tick for Authprofile given pipeline options
   *
   * @param options Pipeline options
   * @return String
   */
  public static String buildConfigurationTick(AuthProfileOptions options) throws IOException {
    CfgTickBuilder b = new CfgTickBuilder().includePipelineOptions(options);

    if (options.getEnableStateAnalysis()) {
      b.withTransformDoc(new StateAnalyze(options));
    }
    if (options.getEnableCritObjectAnalysis()) {
      b.withTransformDoc(new CritObjectAnalyze(options));
    }

    return b.build();
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

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      alertList =
          alertList.and(
              events
                  .apply(
                      "cfgtick processor",
                      ParDo.of(new CfgTickProcessor("authprofile-cfgtick", "category")))
                  .apply(new GlobalTriggers<Alert>(5)));
    }

    return alertList.apply("flatten output", Flatten.<Alert>pCollections());
  }

  private static void runAuthProfile(AuthProfileOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    // Register email and slack alert templates
    options.setOutputAlertTemplates(ALERT_TEMPLATES);

    PCollection<String> input;
    try {
      input =
          p.apply("input", Input.compositeInputAdapter(options, buildConfigurationTick(options)));
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
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
