package com.mozilla.secops.authprofile;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;

/**
 * Manages and stores state for a given user
 *
 * <p>Used by {@link AuthProfile}.
 */
public class StateModel {
  private static final long DEFAULTPRUNEAGE = 864000L * 3; // 30 days
  private static final long DEFAULTEXPIREAGE = 864000L; // 10 days

  private String subject;
  private Map<String, ModelEntry> entries;

  /** Represents a single known source for authentication for a given user */
  @JsonIgnoreProperties(ignoreUnknown = true)
  static class ModelEntry {
    private Double longitude;
    private Double latitude;
    private DateTime timestamp;

    /**
     * Set model latitude field
     *
     * @param latitude Latitude double value
     */
    public void setLatitude(Double latitude) {
      this.latitude = latitude;
    }

    /**
     * Get model latitude field
     *
     * @return model latitude double value
     */
    @JsonProperty("latitude")
    public Double getLatitude() {
      return latitude;
    }

    /**
     * Set model longitude field
     *
     * @param longitude longitude double value
     */
    public void setLongitude(Double longitude) {
      this.longitude = longitude;
    }

    /**
     * Get model longitude field
     *
     * @return model longitude double value
     */
    @JsonProperty("longitude")
    public Double getLongitude() {
      return longitude;
    }

    /**
     * Get timestamp of entry
     *
     * @return Timestamp as DateTime
     */
    @JsonProperty("timestamp")
    public DateTime getTimestamp() {
      return timestamp;
    }

    /**
     * Set timestamp of entry
     *
     * @param ts Entry timestamp
     */
    public void setTimestamp(DateTime ts) {
      timestamp = ts;
    }

    /**
     * Return true if ModelEntry's timestamp is older than DEFAULTEXPIREAGE.
     *
     * @return Boolean
     */
    public boolean isExpired() {
      long mts = timestamp.getMillis() / 1000;
      if ((DateTimeUtils.currentTimeMillis() / 1000) - mts > DEFAULTEXPIREAGE) {
        return true;
      }
      return false;
    }

    ModelEntry() {}
  }

  /** Prune entries with timestamp older than default model duration */
  public void pruneState() {
    pruneState(DEFAULTPRUNEAGE);
  }

  /**
   * Prune entries with timestamp older than specified duration from state model
   *
   * @param age Prune entries older than specified seconds
   */
  public void pruneState(Long age) {
    Iterator<?> it = entries.entrySet().iterator();
    while (it.hasNext()) {
      Map.Entry<?, ?> p = (Map.Entry) it.next();
      ModelEntry me = (ModelEntry) p.getValue();
      long mts = me.getTimestamp().getMillis() / 1000;
      if ((DateTimeUtils.currentTimeMillis() / 1000) - mts > age) {
        it.remove();
      }
    }
  }

  /**
   * Update state entry for user to indicate authentication from address
   *
   * <p>Note this function does not write the new state, set must be called to make changes
   * permanent.
   *
   * @param ipaddr IP address to update state with
   * @param latitude IP address's latitude
   * @param longitude IP address's longitude
   * @return True if the IP address was unknown, otherwise false
   */
  public Boolean updateEntry(String ipaddr, Double latitude, Double longitude) {
    return updateEntry(ipaddr, new DateTime(), latitude, longitude);
  }

  /**
   * Update state entry for user to indicate authentication from address setting specified timestamp
   * on the entry
   *
   * <p>Note this function does not write the new state, set must be called to make changes
   * permanent.
   *
   * @param ipaddr IP address to update state with
   * @param timestamp Timestamp to associate with update
   * @param latitude IP address's latitude
   * @param longitude IP address's longitude
   * @return True if the IP address was unknown or expired, otherwise false
   */
  public Boolean updateEntry(String ipaddr, DateTime timestamp, Double latitude, Double longitude) {
    ModelEntry ent = entries.get(ipaddr);
    if (ent == null) { // New entry for this user model
      ent = new ModelEntry();
      ent.setTimestamp(timestamp);
      ent.setLatitude(latitude);
      ent.setLongitude(longitude);
      entries.put(ipaddr, ent);
      return true;
    }

    // Otherwise entry is known, check if expired
    Boolean expired = false;
    if (ent.isExpired()) {
      expired = true;
    }
    // Update the entry either way
    ent.setTimestamp(timestamp);
    ent.setLatitude(latitude);
    ent.setLongitude(longitude);
    return expired;
  }

  /**
   * Get the most recent entry, or return null if there are no entries
   *
   * @return {@link StateModel.ModelEntry}
   */
  @JsonIgnore
  public ModelEntry getLatestEntry() {
    ModelEntry mostRecent = null;
    for (ModelEntry me : entries.values()) {
      if (mostRecent == null) {
        mostRecent = me;
      } else {
        if (me.getTimestamp().isAfter(mostRecent.getTimestamp())) {
          mostRecent = me;
        }
      }
    }
    return mostRecent;
  }

  /**
   * Get entries associated with model
   *
   * @return Map of model entries
   */
  @JsonProperty("entries")
  public Map<String, ModelEntry> getEntries() {
    return entries;
  }

  /**
   * Get subject associated with model
   *
   * @return Subject string
   */
  @JsonProperty("subject")
  public String getSubject() {
    return subject;
  }

  /**
   * Set subject associated with model
   *
   * @param subject Subject string
   */
  public void setSubject(String subject) {
    this.subject = subject;
  }

  /**
   * Retrieve state object for user
   *
   * @param user Subject name to retrieve state for
   * @param s Initialized state cursor for request
   * @return User {@link StateModel} or null if it does not exist
   */
  public static StateModel get(String user, StateCursor s) throws StateException {
    StateModel ret = s.get(user, StateModel.class);
    if (ret == null) {
      return null;
    }
    ret.pruneState();
    return ret;
  }

  /**
   * Persist state using state interface
   *
   * <p>Calling set will also commit and close the cursor.
   *
   * @param s Initialized state cursor for request
   */
  public void set(StateCursor s) throws StateException {
    s.set(subject, this);
    s.commit();
  }

  /**
   * Create new state model for user
   *
   * @param subject Subject user name
   */
  @JsonCreator
  public StateModel(@JsonProperty("subject") String subject) {
    this.subject = subject;
    entries = new HashMap<String, ModelEntry>();
  }
}
