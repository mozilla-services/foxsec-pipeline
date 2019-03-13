package com.mozilla.secops.authprofile;

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
import com.mozilla.secops.state.StateException;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.regex.Pattern;
import org.apache.beam.sdk.Pipeline;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.GroupByKey;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.transforms.windowing.AfterProcessingTime;
import org.apache.beam.sdk.transforms.windowing.GlobalWindows;
import org.apache.beam.sdk.transforms.windowing.Repeatedly;
import org.apache.beam.sdk.transforms.windowing.Window;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link AuthProfile} implements analysis of normalized authentication events to detect
 * authentication for a given user from an unknown source IP address.
 *
 * <p>This pipeline can make use of various methods for persistent state storage.
 */
public class AuthProfile implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * Composite transform to parse a {@link PCollection} containing events as strings and emit a
   * {@link PCollection} of {@link KV} objects where the key is a particular username and the value
   * is a list of authentication events seen for that user within the window.
   *
   * <p>The output is windowed in the global window with a trigger which fires every 60 seconds.
   */
  public static class ParseAndWindow
      extends PTransform<PCollection<String>, PCollection<KV<String, Iterable<Event>>>> {
    private static final long serialVersionUID = 1L;

    private Logger log;
    private final String idmanagerPath;
    private final String[] ignoreUserRegex;
    private final Boolean ignoreUnknownIdentities;
    private final ParserCfg cfg;

    /**
     * Static initializer for {@link ParseAndWindow} using specified pipeline options
     *
     * @param options Pipeline options
     */
    public ParseAndWindow(AuthProfileOptions options) {
      idmanagerPath = options.getIdentityManagerPath();
      log = LoggerFactory.getLogger(ParseAndWindow.class);
      ignoreUserRegex = options.getIgnoreUserRegex();
      ignoreUnknownIdentities = options.getIgnoreUnknownIdentities();
      cfg = ParserCfg.fromInputOptions(options);
    }

    @Override
    public PCollection<KV<String, Iterable<Event>>> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();

      // We are interested in both AUTH here (which indicates an authentication activity) and
      // in AUTH_SESSION (which indicates on-going use of an already authenticated session)
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH));
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH_SESSION));

      return col.apply(
              ParDo.of(new ParserDoFn().withConfiguration(cfg).withInlineEventFilter(filter)))
          .apply(
              ParDo.of(
                  new DoFn<Event, KV<String, Event>>() {
                    private static final long serialVersionUID = 1L;

                    private IdentityManager idmanager;
                    private Pattern[] ignoreUsers;

                    @Setup
                    public void setup() throws IOException {
                      idmanager = IdentityManager.load(idmanagerPath);

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

                      if (n.getSubjectUser() == null) {
                        return;
                      }

                      if (ignoreUsers != null) {
                        for (Pattern p : ignoreUsers) {
                          if (p.matcher(n.getSubjectUser()).matches()) {
                            log.info("{}: ignoring event for ignored user", n.getSubjectUser());
                            return;
                          }
                        }
                      }

                      String identityKey = idmanager.lookupAlias(n.getSubjectUser());
                      if (identityKey != null) {
                        log.info("{}: resolved identity to {}", n.getSubjectUser(), identityKey);
                        c.output(KV.of(identityKey, e));
                      } else {
                        // Don't bother logging for known Kubernetes system users
                        if (!(n.getSubjectUser().equals("system:unsecured")
                            || n.getSubjectUser().equals("cluster-autoscaler")
                            || n.getSubjectUser()
                                .equals("system:serviceaccount:kube-system:endpoint-controller")
                            || n.getSubjectUser().equals("system:kube-proxy"))) {
                          log.info(
                              "{}: username does not map to any known identity or alias",
                              n.getSubjectUser());
                        }
                        if (ignoreUnknownIdentities) {
                          return;
                        }
                        c.output(KV.of(n.getSubjectUser(), e));
                      }
                    }
                  }))
          .apply(
              Window.<KV<String, Event>>into(new GlobalWindows())
                  .triggering(
                      Repeatedly.forever(
                          AfterProcessingTime.pastFirstElementInPane()
                              .plusDelayOf(Duration.standardSeconds(60))))
                  .discardingFiredPanes())
          .apply(GroupByKey.<String, Event>create());
    }
  }

  /**
   * Analyze grouped events for a given user, generating alert messages based on the contents of the
   * authentication event.
   */
  public static class Analyze extends DoFn<KV<String, Iterable<Event>>, Alert> {
    private static final long serialVersionUID = 1L;

    private final String memcachedHost;
    private final Integer memcachedPort;
    private final String datastoreNamespace;
    private final String datastoreKind;
    private final String idmanagerPath;
    private IdentityManager idmanager;
    private Logger log;
    private State state;

    /**
     * Static initializer for {@link Analyze} using specified pipeline options
     *
     * @param options Pipeline options for {@link AuthProfile}
     */
    public Analyze(AuthProfileOptions options) {
      memcachedHost = options.getMemcachedHost();
      memcachedPort = options.getMemcachedPort();
      datastoreNamespace = options.getDatastoreNamespace();
      datastoreKind = options.getDatastoreKind();
      idmanagerPath = options.getIdentityManagerPath();
    }

    @Setup
    public void setup() throws StateException, IOException {
      log = LoggerFactory.getLogger(Analyze.class);

      idmanager = IdentityManager.load(idmanagerPath);

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

    /**
     * Create a base {@link Alert} using information from the event
     *
     * @param e Event
     * @return Base alert object
     */
    private Alert createBaseAlert(Event e) {
      Alert a = new Alert();

      Normalized n = e.getNormalized();
      a.addMetadata("object", n.getObject());
      a.addMetadata("username", n.getSubjectUser());
      a.addMetadata("sourceaddress", n.getSourceAddress());
      a.setCategory("authprofile");

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

      return a;
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

    private void buildAlertPayload(Alert a) {
      String payload =
          String.format(
              "An authentication event for user %s was detected to access %s from %s [%s/%s].",
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
        Alert a = createBaseAlert(e);

        if (identity == null) {
          a.addMetadata("identity_untracked", "true");
          // New/known do not apply for untracked, but just use the new address ignore list here
          if (ignoreDuplicateSourceAddress(e, seenNewAddresses)) {
            continue;
          }
        } else {
          a.addMetadata("identity_key", userIdentity);
          // The event was for a tracked identity, initialize the state model
          StateModel sm = StateModel.get(userIdentity, state);
          if (sm == null) {
            sm = new StateModel(userIdentity);
          }

          if (sm.updateEntry(e.getNormalized().getSourceAddress())) {
            // Check new address ignore list
            if (ignoreDuplicateSourceAddress(e, seenNewAddresses)) {
              continue;
            }
            // Address was new
            log.info(
                "{}: escalating alert criteria for new source: {} {}",
                userIdentity,
                e.getNormalized().getSubjectUser(),
                e.getNormalized().getSourceAddress());
            a.setSeverity(Alert.AlertSeverity.WARNING);
            a.setTemplateName("authprofile.ftlh");
            addEscalationMetadata(a, identity);
          } else {
            // Check known address ignore list
            if (ignoreDuplicateSourceAddress(e, seenKnownAddresses)) {
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
            sm.set(state);
          } catch (StateException exc) {
            log.error("{}: error updating state: {}", userIdentity, exc.getMessage());
          }
        }

        buildAlertSummary(e, a);
        buildAlertPayload(a);
        c.output(a);
      }
    }
  }

  /** Runtime options for {@link AuthProfile} pipeline. */
  public interface AuthProfileOptions extends PipelineOptions, InputOptions, OutputOptions {
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
  }

  private static void runAuthProfile(AuthProfileOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    p.apply("input", new CompositeInput(options))
        .apply("parse and window", new ParseAndWindow(options))
        .apply(ParDo.of(new Analyze(options)))
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
