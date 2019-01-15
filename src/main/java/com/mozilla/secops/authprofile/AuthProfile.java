package com.mozilla.secops.authprofile;

import com.mozilla.secops.InputOptions;
import com.mozilla.secops.OutputOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertFormatter;
import com.mozilla.secops.identity.Identity;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.EventFilterPayload;
import com.mozilla.secops.parser.EventFilterRule;
import com.mozilla.secops.parser.Normalized;
import com.mozilla.secops.parser.ParserDoFn;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;
import java.io.IOException;
import java.io.Serializable;
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
   * <p>The output is windowed in the global window with a trigger which fires every 30 seconds.
   */
  public static class ParseAndWindow
      extends PTransform<PCollection<String>, PCollection<KV<String, Iterable<Event>>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Iterable<Event>>> expand(PCollection<String> col) {
      EventFilter filter = new EventFilter();
      filter.addRule(new EventFilterRule().wantNormalizedType(Normalized.Type.AUTH));
      filter.addKeyingSelector(
          new EventFilterRule()
              .addPayloadFilter(
                  new EventFilterPayload()
                      .withStringSelector(
                          EventFilterPayload.StringProperty.NORMALIZED_SUBJECTUSER)));

      return col.apply(ParDo.of(new ParserDoFn()))
          .apply(EventFilter.getKeyingTransform(filter))
          .apply(
              Window.<KV<String, Event>>into(new GlobalWindows())
                  .triggering(
                      Repeatedly.forever(
                          AfterProcessingTime.pastFirstElementInPane()
                              .plusDelayOf(Duration.standardSeconds(30))))
                  .withAllowedLateness(Duration.standardSeconds(30))
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

      if (idmanagerPath == null) {
        idmanager = IdentityManager.loadFromResource();
      } else {
        idmanager = IdentityManager.loadFromResource(idmanagerPath);
      }

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

    @ProcessElement
    public void processElement(ProcessContext c) throws StateException {
      Iterable<Event> events = c.element().getValue();
      String username = c.element().getKey();

      Identity identity = null;
      String identityKey = idmanager.lookupAlias(username);
      String stateKey = username;
      if (identityKey != null) {
        log.info("{}: resolved identity to {}", username, identityKey);
        identity = idmanager.getIdentity(identityKey);
        // If we were able to resolve an identity, use that for the state key instead of the
        // event username
        stateKey = identityKey;
      } else {
        log.warn("{}: username does not map to any known identity or alias", username);
      }

      for (Event e : events) {
        Normalized n = e.getNormalized();
        String address = n.getSourceAddress();
        String destination = n.getObject();
        Boolean isUnknown = false;

        StateModel sm = StateModel.get(stateKey, state);
        if (sm == null) {
          sm = new StateModel(stateKey);
        }

        String city = n.getSourceAddressCity();
        String country = n.getSourceAddressCountry();
        String summaryIndicator = address;
        if (city != null && country != null) {
          summaryIndicator = String.format("%s/%s", city, country);
        }

        Alert alert = new Alert();

        String summary = String.format("%s authenticated to %s", username, destination);
        if (sm.updateEntry(address)) {
          // Address was new
          isUnknown = true;
          log.info("{}: escalating alert criteria for new source: {}", username, address);
          summary = summary + " from new source, " + summaryIndicator;
          alert.setSeverity(Alert.AlertSeverity.WARNING);
          alert.setTemplateName("authprofile.ftlh");

          alert.addToPayload(
              String.format(
                  "An authentication event for user %s was detected "
                      + "to access %s, and this event occurred from a source address unknown to the system.",
                  username, destination));
        } else {
          // Known source
          log.info("{}: access from known source: {}", username, address);
          summary = summary + " from " + summaryIndicator;
          alert.setSeverity(Alert.AlertSeverity.INFORMATIONAL);
          alert.addToPayload(
              String.format(
                  "An authentication event for user %s was detected "
                      + "to access %s. This occurred from a known source address.",
                  username, destination));
        }
        alert.setSummary(summary);
        alert.setCategory("authprofile");

        alert.addMetadata("object", destination);
        alert.addMetadata("sourceaddress", address);
        alert.addMetadata("username", username);
        if (identityKey != null) {
          alert.addMetadata("identity_key", identityKey);
          // If new, set direct notification in the metadata so the alert is also forwarded
          // to the user.
          if (isUnknown) {
            String dnot = identity.getEmailNotifyDirect(idmanager.getDefaultNotification());
            if (dnot != null) {
              log.info(
                  "{}: adding direct email notification metadata route to {}", identityKey, dnot);
              alert.addMetadata("notify_email_direct", dnot);

              // TODO: Uncomment to enable slack direct message alerts
              // log.info("{}: adding slack notification metadata to {}", identityKey, dnot);
              // alert.addMetadata("notify_slack_direct", dnot);
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

        sm.set(state);
        c.output(alert);
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

    @Description("Override default identity manager configuration; resource path")
    String getIdentityManagerPath();

    void setIdentityManagerPath(String value);
  }

  private static void runAuthProfile(AuthProfileOptions options) throws IllegalArgumentException {
    Pipeline p = Pipeline.create(options);

    PCollection<KV<String, Iterable<Event>>> events =
        p.apply("input", options.getInputType().read(p, options))
            .apply("parse and window", new ParseAndWindow());

    PCollection<String> alerts =
        events
            .apply(ParDo.of(new Analyze(options)))
            .apply("output format", ParDo.of(new AlertFormatter()));

    alerts.apply("output", OutputOptions.compositeOutput(options));

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
