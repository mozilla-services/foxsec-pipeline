package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import java.util.Objects;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link Watchlist} is used by pipelines to query watchlist entries stored within Datastore. */
public class Watchlist {

  private Logger log;
  private State ipState;
  private State emailState;

  /** Namespace for watchlist entries in Datastore */
  public static final String watchlistDatastoreNamespace = "watchlist";

  /** Kind for watchlist IP entry in Datastore */
  public static final String watchlistIpKind = "ip";

  /** Kind for watchlist email entry in Datastore */
  public static final String watchlistEmailKind = "email";

  public static class WatchlistEntry {
    private String obj;
    private String type;
    private Alert.AlertSeverity severity;
    private DateTime expiresAt;
    private String createdBy;

    /**
     * Get object string
     *
     * @return object string
     */
    @JsonProperty("object")
    public String getObject() {
      return obj;
    }

    /**
     * Set object string
     *
     * @param obj object string
     */
    public void setObject(String obj) {
      this.obj = obj;
    }

    /**
     * Get type string
     *
     * @return type string
     */
    @JsonProperty("type")
    public String getType() {
      return type;
    }

    /**
     * Set type string
     *
     * @param type type string
     */
    public void setType(String type) {
      this.type = type;
    }

    /**
     * Set severity
     *
     * @param severity Severity
     */
    public void setSeverity(Alert.AlertSeverity severity) {
      this.severity = severity;
    }

    /**
     * Get severity
     *
     * @return Severity
     */
    @JsonProperty("severity")
    public Alert.AlertSeverity getSeverity() {
      return severity;
    }

    /**
     * Get expires at
     *
     * @return DateTime
     */
    @JsonProperty("expires_at")
    public DateTime getExpiresAt() {
      return expiresAt;
    }

    /**
     * Set expires at
     *
     * @param expiresAt DateTime
     */
    public void setExpiresAt(DateTime expiresAt) {
      this.expiresAt = expiresAt;
    }

    /**
     * Get created by value
     *
     * @return Created by
     */
    @JsonProperty("created_by")
    public String getCreatedBy() {
      return createdBy;
    }

    /**
     * Set created by value
     *
     * @param createdBy Created by
     */
    public void setCreatedBy(String createdBy) {
      this.createdBy = createdBy;
    }

    @Override
    public boolean equals(Object o) {
      if (!(o instanceof WatchlistEntry)) {
        return false;
      }
      WatchlistEntry t = (WatchlistEntry) o;
      return getCreatedBy().equals(t.getCreatedBy())
          && getType().equals(t.getType())
          && getObject().equals(t.getObject())
          && getSeverity().equals(t.getSeverity())
          && getExpiresAt().isEqual(t.getExpiresAt().toInstant());
    }

    @Override
    public int hashCode() {
      return Objects.hash(getType() + getObject());
    }

    /**
     * Return JSON string representation.
     *
     * @return String or null if serialization fails.
     */
    public String toJSON() {
      ObjectMapper mapper = new ObjectMapper();
      mapper.registerModule(new JodaModule());
      mapper.configure(
          com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
      try {
        return mapper.writeValueAsString(this);
      } catch (JsonProcessingException exc) {
        return null;
      }
    }
  }

  /**
   * Return a new watchlist interface for fetching watchlist entries
   *
   * @return Watchlist
   */
  public Watchlist() throws StateException {
    log = LoggerFactory.getLogger(Watchlist.class);
    ipState = new State(new DatastoreStateInterface(watchlistIpKind, watchlistDatastoreNamespace));
    ipState.initialize();
    emailState =
        new State(new DatastoreStateInterface(watchlistEmailKind, watchlistDatastoreNamespace));
    emailState.initialize();
  }

  /**
   * Return a new watchlist interface for fetching watchlist entries
   *
   * <p>Supports specifiying a GCP project name where the watchlist entries are stored in Datastore
   *
   * @param datastoreProject GCP project name that contains the watchlist entries
   * @return Watchlist
   */
  public Watchlist(String datastoreProject) throws StateException {
    log = LoggerFactory.getLogger(Watchlist.class);
    ipState =
        new State(
            new DatastoreStateInterface(
                watchlistIpKind, watchlistDatastoreNamespace, datastoreProject));
    ipState.initialize();
    emailState =
        new State(
            new DatastoreStateInterface(
                watchlistEmailKind, watchlistDatastoreNamespace, datastoreProject));
    emailState.initialize();
  }

  /**
   * Get a watchlist entry of the specific type with the specified obj identifier. Returns null if
   * not found.
   *
   * @param type Type of watchlist entry (email, ip, etc)
   * @param obj The obj to try and get
   * @return WatchlistEntry, or null if not found
   */
  public WatchlistEntry getWatchlistEntry(String type, String obj) {
    State s;
    if (type.equals(watchlistEmailKind)) {
      s = emailState;
    } else if (type.equals(watchlistIpKind)) {
      s = ipState;
    } else {
      return null;
    }

    WatchlistEntry entry;
    try {
      entry = s.get(obj, WatchlistEntry.class);
    } catch (StateException exc) {
      log.error("Error watchlist entry of type {}: {}", type, exc.getMessage());
      return null;
    }

    return entry;
  }

  private WatchlistEntry[] getWatchedObjects(String type) {
    State s;
    if (type.equals(watchlistEmailKind)) {
      s = emailState;
    } else if (type.equals(watchlistIpKind)) {
      s = ipState;
    } else {
      return null;
    }

    WatchlistEntry[] entries;
    try {
      entries = s.getAll(WatchlistEntry.class);
    } catch (StateException exc) {
      log.error("Error getting all watched {}: {}", type, exc.getMessage());
      return null;
    }

    return entries;
  }

  /**
   * Returns watched email addresses
   *
   * @return Array of WatchlistEntry of type "email"
   */
  public WatchlistEntry[] getWatchedEmails() {
    return getWatchedObjects(watchlistEmailKind);
  }

  /**
   * Returns watched ip addresses
   *
   * @return Array of WatchlistEntry of type "ip"
   */
  public WatchlistEntry[] getWatchedIPs() {
    return getWatchedObjects(watchlistIpKind);
  }

  /**
   * Closes state interfaces to datastore. Must be called when finished using the instantiated
   * {@link Watchlist}
   */
  public void done() {
    ipState.done();
    emailState.done();
  }

  /** main routine used to create watchlist entries. */
  public static void main(String[] args) throws Exception {
    Options options = new Options();

    Option object = new Option("o", "object", true, "Object to watch. Can be an IP or email.");
    object.setRequired(true);
    options.addOption(object);

    Option type = new Option("t", "type", true, "Type of object to watch. Can be 'ip' or 'email'");
    type.setRequired(true);
    options.addOption(type);

    Option createdby = new Option("c", "createdby", true, "");
    createdby.setRequired(true);
    options.addOption(createdby);

    Option severity =
        new Option(
            "s", "severity", true, "Severity of Watchlist entry. Can be 'info', 'warn', or 'crit'");
    severity.setRequired(true);
    options.addOption(severity);

    Option neverexpires =
        new Option(
            "ne",
            "neverexpires",
            false,
            "Watchlist entry never expires (compared to default of 14 days)");
    options.addOption(neverexpires);

    Option project =
        new Option("p", "project", true, "GCP project name (required if submitting to Datastore)");
    options.addOption(project);

    Option submit =
        new Option(
            "su", "submit", false, "Submit Watchlist entry to Datastore rather than emit json");
    options.addOption(submit);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter fmt = new HelpFormatter();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      fmt.printHelp("Watchlist", options);
      System.exit(1);
    }

    Watchlist.WatchlistEntry we = new Watchlist.WatchlistEntry();
    if (!cmd.getOptionValue("type").equals("email") && !cmd.getOptionValue("type").equals("ip")) {
      System.out.println("Unsupported --type: " + cmd.getOptionValue("type"));
      fmt.printHelp("Watchlist", options);
      System.exit(1);
    }

    we.setType(cmd.getOptionValue("type"));
    we.setObject(cmd.getOptionValue("object"));
    we.setCreatedBy(cmd.getOptionValue("createdby"));

    // Parse severity based on text arg
    if (cmd.getOptionValue("severity").equals("info")) {
      we.setSeverity(Alert.AlertSeverity.INFORMATIONAL);
    } else if (cmd.getOptionValue("severity").equals("info")) {
      we.setSeverity(Alert.AlertSeverity.WARNING);
    } else if (cmd.getOptionValue("severity").equals("info")) {
      we.setSeverity(Alert.AlertSeverity.CRITICAL);
    } else {
      System.out.println("Got unknown severity option: " + cmd.getOptionValue("severity"));
      fmt.printHelp("Watchlist", options);
      System.exit(1);
    }

    // Set expiration
    if (cmd.hasOption("neverexpires")) {
      DateTime d = new DateTime();
      d = d.plusYears(50);
      we.setExpiresAt(d);
    } else {
      DateTime d = new DateTime();
      d = d.plusDays(14);
      we.setExpiresAt(d);
    }

    // Submit to datastore if option(s) are present
    if (cmd.hasOption("su")) {
      if (cmd.getOptionValue("p", null) == null) {
        System.out.println("--project required with --submit");
        fmt.printHelp("Watchlist", options);
        System.exit(1);
      }

      String kind = watchlistIpKind;
      if (we.getType().equals("email")) {
        kind = watchlistEmailKind;
      }

      State s =
          new State(
              new DatastoreStateInterface(
                  kind, Watchlist.watchlistDatastoreNamespace, cmd.getOptionValue("p")));
      s.initialize();
      StateCursor c = s.newCursor();
      c.set(we.getObject(), we);
      c.commit();
      s.done();
      System.out.println("Successfully submitted watchlist entry to " + cmd.getOptionValue("p"));
    }

    String weJson = we.toJSON();
    System.out.println(weJson);
  }
}
