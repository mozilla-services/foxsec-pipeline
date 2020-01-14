package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;
import java.util.Objects;
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
}
