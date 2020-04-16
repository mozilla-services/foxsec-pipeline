package com.mozilla.secops.authprofile;

import com.mozilla.secops.CidrUtil;
import com.mozilla.secops.DocumentingTransform;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.Minfraud;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.alert.AlertMeta;
import com.mozilla.secops.alert.AlertSuppressor;
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
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.options.Validation;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.MapElements;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.joda.time.Duration;
import org.joda.time.Instant;
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

  private static IdentityManager globalIdm;
  private static Instant globalIdmLoaded;
  private static ReentrantLock globalIdmLock = new ReentrantLock();
  private static final Duration globalIdmRefresh = Duration.standardMinutes(5);

  /**
   * Load a process shared version of the identity manager
   *
   * <p>Requests the current identity manager for use. In an attempt to be as consistent as possible
   * across worker threads, the identity manager is shared. If the identity manager is more than 5
   * minutes old, a new version is requested from storage.
   *
   * <p>This function will pick up a mutex on entry which is released on return.
   *
   * @param path Identity manager path
   * @return IdentityManager
   * @throws IOException IOException
   */
  public static IdentityManager getIdentityManager(String path) throws IOException {
    globalIdmLock.lock();
    try {
      if ((globalIdmLoaded == null)
          || (new Instant().isAfter(globalIdmLoaded.plus(globalIdmRefresh)))) {
        globalIdmLoaded = new Instant();
        globalIdm = IdentityManager.load(path);
      }
      return globalIdm;
    } finally {
      globalIdmLock.unlock();
    }
  }

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

                        // Auto-ignore certain GCP audit records for service accounts
                        if (n.getSubjectUser().startsWith("system:serviceaccount:")
                            || n.getSubjectUser().startsWith("system:node:")
                            || n.getSubjectUser()
                                .endsWith("@gcp-sa-logging.iam.gserviceaccount.com")
                            || n.getSubjectUser().endsWith("@system.gserviceaccount.com")) {
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
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      Event e = c.element();
      Normalized n = e.getNormalized();
      IdentityManager idmanager;

      try {
        idmanager = AuthProfile.getIdentityManager(idmanagerPath);
      } catch (IOException exc) {
        throw new RuntimeException(exc.getMessage());
      }

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
  public static class CritObjectAnalyze extends DoFn<Event, KV<String, Alert>>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    private final String[] critObjects;
    private final String critNotifyEmail;
    private final String contactEmail;
    private final String docLink;
    private final boolean useEventTimestampForAlert;

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
      useEventTimestampForAlert = options.getUseEventTimestampForAlert();
    }

    /** {@inheritDoc} */
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
  }

  /**
   * Analyze grouped events associated with a particular user or identity against persistent user
   * state
   */
  public static class StateAnalyze extends DoFn<KV<String, Iterable<Event>>, Alert>
      implements DocumentingTransform {
    private static final long serialVersionUID = 1L;

    /**
     * The outcome of state analysis can result in various actions being taken. The metadata action
     * type field present in the generated alert controls how various payload text and other
     * attributes are set.
     */
    public enum ActionType {
      /** Known IP for identity */
      KNOWN_IP("known_ip"),
      /** Unknown IP, but within GeoIP distance of previous known source address */
      UNKNOWN_IP_WITHIN_GEO("unknown_ip_within_geo"),
      /** Unknown IP, and outside GeoIP distance of previous known source address */
      UNKNOWN_IP_OUTSIDE_GEO("unknown_ip_outside_geo"),
      /** Unknown IP, and minFraud hosting provider indication */
      UNKNOWN_IP_HOSTING_PROVIDER("unknown_ip_hosting_provider"),
      /** Unknown IP, and minFraud anonymity network indication */
      UNKNOWN_IP_ANON_NETWORK("unknown_ip_anon_network"),
      /** Unknown IP, and minFraud or GeoIP resolution failed */
      UNKNOWN_IP_MINFRAUD_GEO_FAILURE("unknown_ip_minfraud_geo_failure"),
      /** Event was GCP internal (GCP address, GCPAUDIT) */
      GCP_INTERNAL("gcp_internal");

      private String text;

      /**
       * Create new action type
       *
       * @param text String
       */
      ActionType(String text) {
        this.text = text;
      }

      @Override
      public String toString() {
        return this.text;
      }

      /**
       * Return ActionType using string format
       *
       * @param text String
       * @return ActionType, or null if string does not match known type
       */
      public static ActionType fromString(String text) {
        for (ActionType i : ActionType.values()) {
          if (i.text.equals(text)) {
            return i;
          }
        }
        return null;
      }
    }

    private final String memcachedHost;
    private final Integer memcachedPort;
    private final String datastoreNamespace;
    private final String datastoreKind;
    private final String idmanagerPath;
    private final Double maxKilometersPerSecond;
    private final String maxmindAccountId;
    private final String maxmindLicenseKey;
    private final Double maxKilometersStatic;
    private final String gcpProject;
    private final String contactEmail;
    private final String docLink;
    private final Boolean useEventTimestampForAlert;
    private CidrUtil cidrGcp;
    private Logger log;
    private State state;
    private Minfraud minfraud;

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
      maxKilometersStatic = options.getMaximumKilometersFromLastLogin();
      maxmindAccountId = options.getMaxmindAccountId();
      maxmindLicenseKey = options.getMaxmindLicenseKey();
      gcpProject = options.getProject();
      contactEmail = options.getContactEmail();
      docLink = options.getDocLink();
      useEventTimestampForAlert = options.getUseEventTimestampForAlert();
    }

    /** {@inheritDoc} */
    public String getTransformDoc() {
      return "Alert if an identity (can be thought of as a user) authenticates from a new IP";
    }

    @Setup
    public void setup() throws StateException, IOException {
      log = LoggerFactory.getLogger(StateAnalyze.class);

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

      if (maxmindAccountId != null || maxmindLicenseKey != null) {
        minfraud = new Minfraud(maxmindAccountId, maxmindLicenseKey, gcpProject);
      }
    }

    @Teardown
    public void teardown() {
      state.done();
    }

    private String getEntryKey(String ipAddr, IdentityManager idmanager) {
      String ret = idmanager.lookupNamedSubnet(ipAddr);
      if (ret != null) {
        return ret;
      }
      return ipAddr;
    }

    private void addEscalationMetadata(
        Alert a, Identity identity, String identityKey, Boolean onlyNotify) {
      if (onlyNotify) {
        if (identity.shouldNotifyViaSlack()) {
          a.addMetadata(
              AlertMeta.Key.NOTIFY_SLACK_DIRECT, a.getMetadataValue(AlertMeta.Key.IDENTITY_KEY));
          a.addMetadata(AlertMeta.Key.ALERT_NOTIFICATION_TYPE, "slack_notification");
        } else if (identity.shouldNotifyViaEmail()) {
          a.addMetadata(AlertMeta.Key.NOTIFY_EMAIL_DIRECT, identity.getNotify().getEmail());
        } else {
          log.info("no notification method set for {}", identityKey);
        }
      } else {
        if (identity.getEscalateTo() != null) {
          a.addMetadata(AlertMeta.Key.ESCALATE_TO, identity.getEscalateTo());
        }
        if (identity.shouldAlertViaSlack()) {
          a.addMetadata(
              AlertMeta.Key.NOTIFY_SLACK_DIRECT, a.getMetadataValue(AlertMeta.Key.IDENTITY_KEY));
          a.addMetadata(AlertMeta.Key.ALERT_NOTIFICATION_TYPE, "slack_confirmation");
        } else if (identity.shouldAlertViaEmail()) {
          a.addMetadata(AlertMeta.Key.NOTIFY_EMAIL_DIRECT, identity.getAlert().getEmail());
        } else {
          log.info("no alerting method set for {}", identityKey);
        }
      }
    }

    private void buildAlertSummary(Event e, Alert a) {
      String summary =
          String.format(
              "authentication event observed %s [%s] to %s, ",
              e.getNormalized().getSubjectUser(),
              a.getMetadataValue(AlertMeta.Key.IDENTITY_KEY) != null
                  ? a.getMetadataValue(AlertMeta.Key.IDENTITY_KEY)
                  : "untracked",
              e.getNormalized().getObject());
      if (a.getSeverity().equals(Alert.AlertSeverity.WARNING)) {
        summary = summary + "new source ";
      }
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
      String msg = "An authentication event for user %s was detected to access %s from %s [%s/%s].";
      if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
        msg = "A sensitive event from user %s was detected in association with %s from %s [%s/%s].";
      }
      String payload =
          String.format(
              msg,
              a.getMetadataValue(AlertMeta.Key.USERNAME),
              a.getMetadataValue(AlertMeta.Key.OBJECT),
              a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS),
              a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_CITY),
              a.getMetadataValue(AlertMeta.Key.SOURCEADDRESS_COUNTRY));

      if (a.getMetadataValue(AlertMeta.Key.STATE_ACTION_TYPE) == null) {
        throw new RuntimeException("state alert had no action type");
      }
      ActionType at = ActionType.fromString(a.getMetadataValue(AlertMeta.Key.STATE_ACTION_TYPE));
      if (at == null) {
        throw new RuntimeException("state alert had invalid action type");
      }

      switch (at) {
        case KNOWN_IP:
          payload = payload + " This occurred from a known source address.";
          break;
        case UNKNOWN_IP_WITHIN_GEO:
          payload =
              payload
                  + " This occurred from a source address unknown to the system, but "
                  + "near your last authentication event.";
          break;
        case UNKNOWN_IP_OUTSIDE_GEO:
          payload =
              payload
                  + " This occurred from a source address unknown to the system and "
                  + "outside of the allowed range from your last authentication event.";
          break;
        case UNKNOWN_IP_ANON_NETWORK:
          payload =
              payload
                  + " This occurred from a source address unknown to the system "
                  + "and marked as from an anonymity network.";
          break;
        case UNKNOWN_IP_HOSTING_PROVIDER:
          payload =
              payload
                  + " This occurred from a source address unknown to the system "
                  + "and marked as from a hosting provider.";
          break;
        case UNKNOWN_IP_MINFRAUD_GEO_FAILURE:
          payload = payload + " This occurred from a source address unknown to the system.";
          break;
        case GCP_INTERNAL:
          payload = payload + " This occurred from a GCP source IP, and was a GCP audit event.";
          break;
        default:
          throw new RuntimeException("action type could not be handled in payload generation");
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
      IdentityManager idmanager;

      try {
        idmanager = AuthProfile.getIdentityManager(idmanagerPath);
      } catch (IOException exc) {
        throw new RuntimeException(exc.getMessage());
      }
      Identity identity = idmanager.getIdentity(userIdentity);

      ArrayList<String> seenKnownAddresses = new ArrayList<>();

      for (Event e : events) {
        Alert a = AuthProfile.createBaseAlert(e, contactEmail, docLink);
        a.setSubcategory("state_analyze");

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
          a.addMetadata(AlertMeta.Key.ALERTIO_IGNORE_EVENT, "true");
          a.addMetadata(AlertMeta.Key.STATE_ACTION_TYPE, ActionType.GCP_INTERNAL.toString());
          buildAlertSummary(e, a);
          buildAlertPayload(e, a);
          c.output(a);
          continue;
        }

        Boolean onlyNotify = false;
        if (identity == null) {
          a.addMetadata(AlertMeta.Key.IDENTITY_UNTRACKED, "true");
          // We do not keep state for untracked identities, but just use the known address
          // list here to filter any duplicates that are part of this batch
          seenKnownAddresses.add(e.getNormalized().getSourceAddress());
          // We also want to skip AlertIO for untracked identities here
          a.addMetadata(AlertMeta.Key.ALERTIO_IGNORE_EVENT, "true");
        } else {
          // AuthStateModel expects a cursor that has been allocated as a transaction
          StateCursor<AuthStateModel> cur = state.newCursor(AuthStateModel.class, true);

          a.addMetadata(AlertMeta.Key.IDENTITY_KEY, userIdentity);
          // The event was for a tracked identity, initialize the state model
          AuthStateModel sm = AuthStateModel.get(userIdentity, cur, new PruningStrategyEntryAge());
          if (sm == null) {
            sm = new AuthStateModel(userIdentity);
          }

          String entryKey = getEntryKey(e.getNormalized().getSourceAddress(), idmanager);
          if (!entryKey.equals(e.getNormalized().getSourceAddress())) {
            a.addMetadata(AlertMeta.Key.ENTRY_KEY, entryKey);
          }

          if (sm.updateEntry(
              entryKey,
              e.getNormalized().getSourceAddressLatitude(),
              e.getNormalized().getSourceAddressLongitude())) {
            // If we end up here the address was new.
            //
            // Enrich the event with data from minFraud; we only want to do this for unknown
            // addresses to reduce API query volume.
            boolean minfraudOk = false;
            if (minfraud != null) {
              minfraudOk = e.getNormalized().insightsEnrichment(minfraud);
              AuthProfile.insightsEnrichAlert(a, e);
            }

            if (!minfraudOk) {
              // If the address was new, and the minFraud enrichment failed, always escalate
              log.info(
                  "{}: escalating alert criteria for new source (couldn't get minfraud insights): {} {}",
                  userIdentity,
                  e.getNormalized().getSubjectUser(),
                  e.getNormalized().getSourceAddress());
              a.setSeverity(Alert.AlertSeverity.WARNING);
              a.addMetadata(
                  AlertMeta.Key.STATE_ACTION_TYPE,
                  ActionType.UNKNOWN_IP_MINFRAUD_GEO_FAILURE.toString());
              buildAlertPayload(e, a);
            } else if (e.getNormalized().getSourceAddressIsAnonymous() != null
                && e.getNormalized().getSourceAddressIsAnonymous()) {
              // Address was new, and corresponds with an anonymity network, always escalate
              log.info(
                  "{}: escalating alert criteria for new source from anonymity network: {} {}",
                  userIdentity,
                  e.getNormalized().getSubjectUser(),
                  e.getNormalized().getSourceAddress());
              a.setSeverity(Alert.AlertSeverity.WARNING);
              a.addMetadata(
                  AlertMeta.Key.STATE_ACTION_TYPE, ActionType.UNKNOWN_IP_ANON_NETWORK.toString());
              buildAlertPayload(e, a);
            } else if (e.getNormalized().getSourceAddressIsHostingProvider() != null
                && e.getNormalized().getSourceAddressIsHostingProvider()) {
              // Address was new, and corresponds with a hosting provider, always escalate
              log.info(
                  "{}: escalating alert criteria for new source from hosting provider: {} {}",
                  userIdentity,
                  e.getNormalized().getSubjectUser(),
                  e.getNormalized().getSourceAddress());
              a.setSeverity(Alert.AlertSeverity.WARNING);
              a.addMetadata(
                  AlertMeta.Key.STATE_ACTION_TYPE,
                  ActionType.UNKNOWN_IP_HOSTING_PROVIDER.toString());
              buildAlertPayload(e, a);
            } else {
              // If we get this far, it was a new IP and minFraud indicates it was not a hosting
              // provider or anonymity network. Attempt GeoIP analysis.
              AuthStateModel.GeoVelocityResponse geoResp =
                  sm.geoVelocityAnalyzeLatest(maxKilometersPerSecond);
              if (geoResp != null) {
                if (geoResp.getKmDistance() > maxKilometersStatic) {
                  // The GeoIP resolved distance of the new login exceeds our configuration, so
                  // generate an escalation.
                  log.info(
                      "{}: escalating alert criteria for new source outside of allowed distance "
                          + "from last login: {} {}",
                      userIdentity,
                      e.getNormalized().getSubjectUser(),
                      e.getNormalized().getSourceAddress());
                  a.setSeverity(Alert.AlertSeverity.WARNING);
                  a.addMetadata(
                      AlertMeta.Key.STATE_ACTION_TYPE,
                      ActionType.UNKNOWN_IP_OUTSIDE_GEO.toString());
                  buildAlertPayload(e, a);
                } else {
                  // New IP, but within acceptable distance. Generate a notification only.
                  log.info(
                      "{}: creating notification only alert for new source inside of allowed "
                          + "distance from last login: {} {}",
                      userIdentity,
                      e.getNormalized().getSubjectUser(),
                      e.getNormalized().getSourceAddress());
                  a.setSeverity(Alert.AlertSeverity.WARNING);
                  a.addMetadata(
                      AlertMeta.Key.STATE_ACTION_TYPE, ActionType.UNKNOWN_IP_WITHIN_GEO.toString());
                  onlyNotify = true;
                  buildAlertPayload(e, a);
                }
              } else {
                // GeoIP analysis failed, generate an escalation.
                log.info(
                    "{}: escalating alert criteria for new source (couldn't get geo velocity information): {} {}",
                    userIdentity,
                    e.getNormalized().getSubjectUser(),
                    e.getNormalized().getSourceAddress());
                a.setSeverity(Alert.AlertSeverity.WARNING);
                a.addMetadata(
                    AlertMeta.Key.STATE_ACTION_TYPE,
                    ActionType.UNKNOWN_IP_MINFRAUD_GEO_FAILURE.toString());
                buildAlertPayload(e, a);
              }
            }
          } else {
            // The address was known
            seenKnownAddresses.add(e.getNormalized().getSourceAddress());
            log.info(
                "{}: access from known source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
            a.addMetadata(AlertMeta.Key.STATE_ACTION_TYPE, ActionType.KNOWN_IP.toString());
            buildAlertPayload(e, a);
          }

          // Update persistent state with new information
          try {
            sm.set(cur, new PruningStrategyEntryAge());
          } catch (StateException exc) {
            log.error("{}: error updating state: {}", userIdentity, exc.getMessage());
          }
        }

        if (a.getSeverity().equals(Alert.AlertSeverity.WARNING)) {
          addEscalationMetadata(a, identity, userIdentity, onlyNotify);
        }
        buildAlertSummary(e, a);
        if (useEventTimestampForAlert) {
          a.setTimestamp(e.getTimestamp());
        }
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

    @Description("Maximum km/hr for location velocity analysis")
    @Default.Integer(800)
    Integer getMaximumKilometersPerHour();

    void setMaximumKilometersPerHour(Integer value);

    @Description("Auth0 Client ids to consider for state analysis (multiple allowed)")
    String[] getAuth0ClientIds();

    void setAuth0ClientIds(String[] value);

    @Description("Maximum kilometers from last login without confirmation alert")
    @Default.Double(20)
    Double getMaximumKilometersFromLastLogin();

    void setMaximumKilometersFromLastLogin(Double value);

    @Description("General contact address used in alert templates; email address")
    @Validation.Required
    String getContactEmail();

    void setContactEmail(String value);

    @Description("URL to documentation link used in alert templates; URL")
    @Validation.Required
    String getDocLink();

    void setDocLink(String value);

    @Description("When generating an alert, try to use the timestamp from the event for the alert")
    @Default.Boolean(false)
    Boolean getUseEventTimestampForAlert();

    void setUseEventTimestampForAlert(Boolean value);
  }

  /**
   * Create a base authprofile {@link Alert} using information from the event
   *
   * @param e Event
   * @param contactEmail General contact email address to set in alert metadata
   * @param docLink URL to documentation link to set in alert metadata
   * @return Base alert object
   */
  public static Alert createBaseAlert(Event e, String contactEmail, String docLink) {
    Alert a = new Alert();

    Normalized n = e.getNormalized();
    a.addMetadata(AlertMeta.Key.OBJECT, n.getObject());
    a.addMetadata(AlertMeta.Key.USERNAME, n.getSubjectUser());
    a.addMetadata(AlertMeta.Key.SOURCEADDRESS, n.getSourceAddress());
    a.addMetadata(AlertMeta.Key.EMAIL_CONTACT, contactEmail);
    a.addMetadata(AlertMeta.Key.DOC_LINK, docLink);
    a.setCategory("authprofile");

    a.setEmailTemplate(EMAIL_TEMPLATE);
    a.setSlackTemplate(SLACK_TEMPLATE);

    String city = n.getSourceAddressCity();
    if (city != null) {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_CITY, city);
    } else {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_CITY, "unknown");
    }
    String country = n.getSourceAddressCountry();
    if (city != null) {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_COUNTRY, country);
    } else {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_COUNTRY, "unknown");
    }
    String tz = n.getSourceAddressTimeZone();
    if (tz != null) {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_TIMEZONE, tz);
    } else {
      a.addMetadata(AlertMeta.Key.SOURCEADDRESS_TIMEZONE, "unknown");
    }

    if (e.getNormalized().isOfType(Normalized.Type.AUTH)) {
      a.addMetadata(AlertMeta.Key.AUTH_ALERT_TYPE, "auth");
    } else if (e.getNormalized().isOfType(Normalized.Type.AUTH_SESSION)) {
      a.addMetadata(AlertMeta.Key.AUTH_ALERT_TYPE, "auth_session");
    }

    DateTime eventTimestamp = e.getTimestamp();
    if (eventTimestamp != null) {
      a.addMetadata(AlertMeta.Key.EVENT_TIMESTAMP, eventTimestamp.toString());

      if (tz != null) {
        DateTimeZone dtz = DateTimeZone.forID(tz);
        if (dtz != null) {
          a.addMetadata(
              AlertMeta.Key.EVENT_TIMESTAMP_SOURCE_LOCAL, eventTimestamp.withZone(dtz).toString());
        }
      }
    }

    return a;
  }

  /**
   * Add minfraud insights data into alert metadata
   *
   * @param e Event
   * @param a Alert
   */
  public static void insightsEnrichAlert(Alert a, Event e) {
    Normalized n = e.getNormalized();

    if (n.getSourceAddressRiskScore() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_RISKSCORE, String.valueOf(n.getSourceAddressRiskScore()));
    }
    if (n.getSourceAddressIsAnonymous() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_ANONYMOUS,
          String.valueOf(n.getSourceAddressIsAnonymous()));
    }
    if (n.getSourceAddressIsAnonymousVpn() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_ANONYMOUS_VPN,
          String.valueOf(n.getSourceAddressIsAnonymousVpn()));
    }
    if (n.getSourceAddressIsHostingProvider() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_HOSTING_PROVIDER,
          String.valueOf(n.getSourceAddressIsHostingProvider()));
    }
    if (n.getSourceAddressIsLegitimateProxy() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_LEGITIMATE_PROXY,
          String.valueOf(n.getSourceAddressIsLegitimateProxy()));
    }
    if (n.getSourceAddressIsPublicProxy() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_PUBLIC_PROXY,
          String.valueOf(n.getSourceAddressIsPublicProxy()));
    }
    if (n.getSourceAddressIsTorExitNode() != null) {
      a.addMetadata(
          AlertMeta.Key.SOURCEADDRESS_IS_TOR_EXIT_NODE,
          String.valueOf(n.getSourceAddressIsTorExitNode()));
    }
  }

  /**
   * Build a configuration tick for Authprofile given pipeline options
   *
   * @param options Pipeline options
   * @return String
   * @throws IOException IOException
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

  /**
   * Process input collection
   *
   * <p>Process collection of input events, returning a collection of alerts as required.
   *
   * @param input Input collection
   * @param options Pipeline options
   * @return Output collection
   */
  public static PCollection<Alert> processInput(
      PCollection<String> input, AuthProfileOptions options) {
    PCollectionList<Alert> alertList = PCollectionList.empty(input.getPipeline());

    PCollection<Event> events = input.apply("parse", new Parse(options));

    // Log any warnings related to the identity manager here during graph construction
    try {
      IdentityManager.load(options.getIdentityManagerPath()).logWarnings();
    } catch (IOException exc) {
      throw new IllegalArgumentException(exc.getMessage());
    }

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
                  .apply("critical object suppression", ParDo.of(new AlertSuppressor(1800L)))
                  .apply(
                      "critical object analyze rewindow for output", new GlobalTriggers<Alert>(5)));
    }

    // If configuration ticks were enabled, enable the processor here too
    if (options.getGenerateConfigurationTicksInterval() > 0) {
      alertList =
          alertList.and(
              events
                  .apply("cfgtick processor", ParDo.of(new CfgTickProcessor("authprofile-cfgtick")))
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
        .apply("output convert", MapElements.via(new AlertFormatter.AlertToString()))
        .apply("output", OutputOptions.compositeOutput(options));

    p.run();
  }

  /**
   * Entry point for Beam pipeline.
   *
   * @param args Runtime arguments.
   * @throws Exception Exception
   */
  public static void main(String[] args) throws Exception {
    PipelineOptionsFactory.register(AuthProfileOptions.class);
    AuthProfileOptions options =
        PipelineOptionsFactory.fromArgs(args).withValidation().as(AuthProfileOptions.class);
    runAuthProfile(options);
  }
}
