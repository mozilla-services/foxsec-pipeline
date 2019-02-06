package com.mozilla.secops.authprofile;

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

    /**
     * Static initializer for {@link ParseAndWindow} using specified pipeline options
     *
     * @param options Pipeline options
     */
    public ParseAndWindow(AuthProfileOptions options) {
      idmanagerPath = options.getIdentityManagerPath();
      log = LoggerFactory.getLogger(ParseAndWindow.class);
      ignoreUserRegex = options.getIgnoreUserRegex();
    }

    @Override
    public PCollection<KV<String, Iterable<Event>>> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();

      // We are interested in both AUTH here (which indicates an authentication activity) and
      // in AUTH_SESSION (which indicates on-going use of an already authenticated session)
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH));
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH_SESSION));

      return col.apply(ParDo.of(new ParserDoFn().withInlineEventFilter(filter)))
          .apply(
              ParDo.of(
                  new DoFn<Event, KV<String, Event>>() {
                    private static final long serialVersionUID = 1L;

                    private IdentityManager idmanager;
                    private Pattern[] ignoreUsers;

                    @Setup
                    public void setup() throws IOException {
                      if (idmanagerPath == null) {
                        idmanager = IdentityManager.loadFromResource();
                      } else {
                        idmanager = IdentityManager.loadFromResource(idmanagerPath);
                      }

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
                        log.info(
                            "{}: username does not map to any known identity or alias",
                            n.getSubjectUser());
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
    private final Boolean memcachedEnabled;
    private final String datastoreNamespace;
    private final String datastoreKind;
    private final Boolean datastoreEnabled;
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
      memcachedEnabled = options.getMemcachedEnabled();
      datastoreNamespace = options.getDatastoreNamespace();
      datastoreKind = options.getDatastoreKind();
      datastoreEnabled = options.getDatastoreEnabled();
      idmanagerPath = options.getIdentityManagerPath();
    }

    @Setup
    public void setup() throws StateException, IOException {
      log = LoggerFactory.getLogger(Analyze.class);

      if (idmanagerPath == null) {
        idmanager = IdentityManager.loadFromResource();
      } else {
        idmanager = IdentityManager.loadFromResource(idmanagerPath);
      }

      if (memcachedEnabled) {
        log.info("using memcached for state management");
        state = new State(new MemcachedStateInterface(memcachedHost, memcachedPort));
      } else if (datastoreEnabled) {
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

    @ProcessElement
    public void processElement(ProcessContext c) throws StateException {
      Iterable<Event> events = c.element().getValue();
      String userIdentity = c.element().getKey();
      Identity identity = idmanager.getIdentity(userIdentity);

      ArrayList<String> seenNew = new ArrayList<>();
      ArrayList<String> seenKnown = new ArrayList<>();

      for (Event e : events) {
        Normalized n = e.getNormalized();
        String address = n.getSourceAddress();
        String destination = n.getObject();
        // The element key will be the possibly resolved identity of the user if we were able
        // to look the user up using identity manager. Grab the original username from the source
        // event as well.
        String eventUsername = n.getSubjectUser();
        Boolean isUnknown = false;

        StateModel sm = StateModel.get(userIdentity, state);
        if (sm == null) {
          sm = new StateModel(userIdentity);
        }

        String city = n.getSourceAddressCity();
        String country = n.getSourceAddressCountry();
        String summaryIndicator = address;
        if (city != null && country != null) {
          summaryIndicator = summaryIndicator + String.format(" [%s/%s]", city, country);
        }

        Alert alert = new Alert();

        String summary =
            String.format("authentication event observed %s to %s", eventUsername, destination);
        if (sm.updateEntry(address)) {
          // Address was new
          Boolean wasSeen = false;
          for (String s : seenNew) {
            if (s.equals(address)) {
              wasSeen = true;
            }
          }
          // If we have already reported this as new once during this window, just ignore
          // this event
          if (wasSeen) {
            continue;
          }
          seenNew.add(address);

          isUnknown = true;
          log.info("{}: escalating alert criteria for new source: {}", userIdentity, address);
          summary = summary + ", new source " + summaryIndicator;
          alert.setSeverity(Alert.AlertSeverity.WARNING);
          alert.setTemplateName("authprofile.ftlh");

          alert.addToPayload(
              String.format(
                  "An authentication event for user %s was detected "
                      + "to access %s, and this event occurred from a source address unknown to the system.",
                  eventUsername, destination));
        } else {
          // Known source
          Boolean wasSeen = false;
          for (String s : seenKnown) {
            if (s.equals(address)) {
              wasSeen = true;
            }
          }
          // If we have already reported this as new once during this window, just ignore
          // this event
          if (wasSeen) {
            continue;
          }
          seenKnown.add(address);

          log.info("{}: access from known source: {}", userIdentity, address);
          summary = summary + ", known source " + summaryIndicator;
          alert.setSeverity(Alert.AlertSeverity.INFORMATIONAL);
          alert.addToPayload(
              String.format(
                  "An authentication event for user %s was detected "
                      + "to access %s. This occurred from a known source address.",
                  eventUsername, destination));
        }
        alert.setSummary(summary);
        alert.setCategory("authprofile");

        alert.addMetadata("object", destination);
        alert.addMetadata("sourceaddress", address);
        alert.addMetadata("username", eventUsername);
        if (identity != null) {
          alert.addMetadata("identity_key", userIdentity);
          // If new, set direct notification in the metadata so the alert is also forwarded
          // to the user.
          if (isUnknown) {
            String dnot = identity.getEmailNotifyDirect(idmanager.getDefaultNotification());
            if (dnot != null) {
              log.info(
                  "{}: adding direct email notification metadata route to {}", userIdentity, dnot);
              alert.addMetadata("notify_email_direct", dnot);
            }

            if (identity.getSlackNotifyDirect(idmanager.getDefaultNotification())) {
              log.info("{}: adding direct slack notification", userIdentity);
              alert.addMetadata("notify_slack_direct", userIdentity);
            }
          }
        }
        if (city != null) {
          alert.addMetadata("sourceaddress_city", city);
        } else {
          alert.addMetadata("sourceaddress_city", "unknown");
        }
        if (country != null) {
          alert.addMetadata("sourceaddress_country", country);
        } else {
          alert.addMetadata("sourceaddress_country", "unknown");
        }

        try {
          sm.set(state);
        } catch (StateException exc) {
          log.error("{}: error updating state: {}", userIdentity, exc.getMessage());
        }
        if (!alert.hasCorrectFields()) {
          throw new IllegalArgumentException("alert has invalid field configuration");
        }
        c.output(alert);
      }
    }
  }

  /** Runtime options for {@link AuthProfile} pipeline. */
  public interface AuthProfileOptions extends PipelineOptions, InputOptions, OutputOptions {
    @Description("Use Datastore state; namespace for entities")
    @Default.String("authprofile")
    String getDatastoreNamespace();

    void setDatastoreNamespace(String value);

    @Description("Use Datastore state; kind for entities")
    @Default.String("authprofile")
    String getDatastoreKind();

    void setDatastoreKind(String value);

    @Description("Override default identity manager configuration; resource path")
    String getIdentityManagerPath();

    void setIdentityManagerPath(String value);

    @Description("Ignore events for any usernames match regex (multiple allowed)")
    String[] getIgnoreUserRegex();

    void setIgnoreUserRegex(String[] value);
  }

  private static void runAuthProfile(AuthProfileOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    p.apply("input", options.getInputType().read(p, options))
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
