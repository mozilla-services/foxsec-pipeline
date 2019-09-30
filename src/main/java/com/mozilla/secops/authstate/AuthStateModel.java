package com.mozilla.secops.authstate;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.GeoUtil;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;

/** Manages and stores authentication state information for a given user identity. */
public class AuthStateModel {
  /**
   * After a particular source IP address has not been seen for a user in DEFAULTPRUNEAGE seconds,
   * it will be removed from the model.
   */
  public static final long DEFAULTPRUNEAGE = 864000L * 3; // 30 days

  /**
   * After a particular source IP address has not been seen for a user in DEFAULTEXPIREAGE seconds,
   * it will be considered "expired". However it will still be present in the stored model.
   */
  public static final long DEFAULTEXPIREAGE = 864000L; // 10 days

  private String subject;
  private Map<String, ModelEntry> entries;

  /** Response to {@link AuthStateModel} GeoVelocity analysis request */
  public static class GeoVelocityResponse {
    private final Long timeDifference;
    private final Double kmDistance;
    private final Boolean maxKmPerSExceeded;

    /**
     * Get difference in time in seconds
     *
     * @return Long
     */
    public Long getTimeDifference() {
      return timeDifference;
    }

    /**
     * Return true if max KM/s was exceeded
     *
     * @return Boolean
     */
    public Boolean getMaxKmPerSecondExceeded() {
      return maxKmPerSExceeded;
    }

    /**
     * Get distance between points in KM
     *
     * @return Double
     */
    public Double getKmDistance() {
      return kmDistance;
    }

    /**
     * Create new GeoVelocityResponse
     *
     * @param timeDifference Time difference in seconds
     * @param kmDistance Distance between points in KM
     */
    public GeoVelocityResponse(Long timeDifference, Double kmDistance, Boolean maxKmPerSExceeded) {
      this.timeDifference = timeDifference;
      this.kmDistance = kmDistance;
      this.maxKmPerSExceeded = maxKmPerSExceeded;
    }
  }

  /** Represents a single known source for authentication for a given user */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ModelEntry {
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
   * <p>This variant of the method will use the current time as the timestamp for the authentication
   * event, instead of accepting a parameter incidating the timestamp to associated with the event.
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
   * @return {@link AuthStateModel.ModelEntry}
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
   * @return User {@link AuthStateModel} or null if it does not exist
   */
  public static AuthStateModel get(String user, StateCursor s) throws StateException {
    AuthStateModel ret = s.get(user, AuthStateModel.class);
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
   * Perform geo-velocity analysis using the latest entries in the model
   *
   * <p>The latest entry in the model (e.g., last known authentication event) is compared against
   * the entry that precedes it. If long/lat information is available, this information is used to
   * calculate the distance between the events and the amount of time that passed between the
   * events.
   *
   * <p>If geo-velocity analysis was possible, a GeoVelocityResponse is returned, null if not.
   *
   * @param maxKmPerSecond The maximum KM per second to use for the analysis
   * @return GeoVelocityResponse or null
   */
  public GeoVelocityResponse geoVelocityAnalyzeLatest(Double maxKmPerSecond) {
    ArrayList<AbstractMap.SimpleEntry<String, ModelEntry>> ent = timeSortedEntries();

    int s = ent.size();
    if (s <= 1) {
      return null;
    }

    AbstractMap.SimpleEntry<String, ModelEntry> prev = ent.get(s - 2);
    AbstractMap.SimpleEntry<String, ModelEntry> cur = ent.get(s - 1);

    // Make sure we have long/lat for both entries
    if ((prev.getValue().getLatitude() == null)
        || (prev.getValue().getLongitude() == null)
        || (cur.getValue().getLatitude() == null)
        || (cur.getValue().getLongitude() == null)) {
      return null;
    }

    Double kmdist =
        GeoUtil.kmBetweenTwoPoints(
            prev.getValue().getLatitude(),
            prev.getValue().getLongitude(),
            cur.getValue().getLatitude(),
            cur.getValue().getLongitude());

    long td =
        (cur.getValue().getTimestamp().getMillis() / 1000)
            - (prev.getValue().getTimestamp().getMillis() / 1000);

    if ((kmdist / td) > maxKmPerSecond) {
      return new GeoVelocityResponse(td, kmdist, true);
    }
    return new GeoVelocityResponse(td, kmdist, false);
  }

  /**
   * Return all entries in AuthStateModel as an array list, sorted by timestamp
   *
   * @return ArrayList
   */
  public ArrayList<AbstractMap.SimpleEntry<String, ModelEntry>> timeSortedEntries() {
    ArrayList<AbstractMap.SimpleEntry<String, ModelEntry>> ret = new ArrayList<>();
    for (Map.Entry<String, ModelEntry> entry : entries.entrySet()) {
      ret.add(new AbstractMap.SimpleEntry<String, ModelEntry>(entry.getKey(), entry.getValue()));
    }
    Collections.sort(
        ret,
        new Comparator<AbstractMap.SimpleEntry<String, ModelEntry>>() {
          @Override
          public int compare(
              AbstractMap.SimpleEntry<String, ModelEntry> lhs,
              AbstractMap.SimpleEntry<String, ModelEntry> rhs) {
            DateTime lhsd = lhs.getValue().getTimestamp();
            DateTime rhsd = rhs.getValue().getTimestamp();
            if (lhsd.isAfter(rhsd)) {
              return 1;
            } else if (lhsd.isBefore(rhsd)) {
              return -1;
            }
            return 0;
          }
        });
    return ret;
  }

  /**
   * Create new state model for user
   *
   * @param subject Subject user name
   */
  @JsonCreator
  public AuthStateModel(@JsonProperty("subject") String subject) {
    this.subject = subject;
    entries = new HashMap<String, ModelEntry>();
  }
}
