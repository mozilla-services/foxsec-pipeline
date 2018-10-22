package com.mozilla.secops.authprofile;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;

import org.joda.time.DateTime;
import org.joda.time.DateTimeUtils;

import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;

import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Manages and stores state for a given user
 */
public class StateModel {
    private final Long DEFAULTPRUNEAGE = 604800L; // 7 days

    private String subject;
    private Map<String, ModelEntry> entries;

    /**
     * Represents a single known source for authentication for a given user
     */
    static class ModelEntry {
        private DateTime timestamp;

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

        ModelEntry() {
        }
    }

    /**
     * Prune entries with timestamp older than default model duration
     */
    public void pruneState() {
        pruneState(DEFAULTPRUNEAGE);
    }

    /**
     * Prune entries with timestamp older than specified duration from state
     * model
     *
     * @param age Prune entries older than specific seconds
     */
    public void pruneState(Long age) {
        Iterator<?> it = entries.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<?, ?> p = (Map.Entry)it.next();
            ModelEntry me = (ModelEntry)p.getValue();
            Long mts = me.getTimestamp().getMillis() / 1000;
            if ((DateTimeUtils.currentTimeMillis() / 1000) - mts > age) {
                it.remove();
            }
        }
    }

    /**
     * Update state entry for user to indicate authentication from address
     *
     * <p>Note this function does not write the new state, set must be called to make
     * changes permanent.
     *
     * @param ipaddr IP address to update state with
     * @return True if the IP address was unknown, otherwise false
     */
    public Boolean updateEntry(String ipaddr) {
        return updateEntry(ipaddr, new DateTime());
    }

    /**
     * Update state entry for user to indicate authentication from address setting
     * specified timestamp on the entry
     *
     * <p>Note this function does not write the new state, set must be called to make
     * changes permanent.
     *
     * @param ipaddr IP address to update state with
     * @param timestamp Timestamp to associate with update
     * @return True if the IP address was unknown, otherwise false
     */
    public Boolean updateEntry(String ipaddr, DateTime timestamp) {
        ModelEntry ent = entries.get(ipaddr);
        if (ent == null) { // New entry for this user model
            ent = new ModelEntry();
            ent.setTimestamp(timestamp);
            entries.put(ipaddr, ent);
            return true;
        }

        // Otherwise entry is known, update the timestamp field
        ent.setTimestamp(timestamp);
        return false;
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

    /** Set subject associated with model
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
     * @param s Initialized state interface for request
     * @return User {@link StateModel} or null if it does not exist
     */
    public static StateModel get(String user, State s) throws StateException {
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
     * @param s Initialized state interface for request
     */
    public void set(State s) throws StateException {
        s.set(subject, this);
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
