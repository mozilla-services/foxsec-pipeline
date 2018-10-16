package com.mozilla.secops.parser;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.util.UUID;

/**
 * Represents a high level event after being processed by a {@link Parser}.
 *
 * <p>After being parsed, all events are guaranteed to have an associated {@link Payload}
 * value which contains information related to a specific type of event.
 *
 * Specific parser implementations may also add {@link Normalized} data fields to the
 * event.
 */
public class Event implements Serializable {
    private static final long serialVersionUID = 1L;

    private Payload<? extends PayloadBase> payload;
    private final UUID eventId;
    private DateTime timestamp;
    private Normalized normalized;

    /**
     * Create a new {@link Event} object.
     *
     * <p>The default timestamp associated with the event is the current time.
     */
    Event() {
        eventId = UUID.randomUUID();
        normalized = new Normalized();

        // Default the event timestamp to creation time
        timestamp = new DateTime(DateTimeZone.UTC);
    }

    @Override
    public boolean equals(Object o) {
        Event t = (Event)o;
        return getEventId().equals(t.getEventId());
    }

    @Override
    public int hashCode() {
        return eventId.hashCode();
    }

    /**
     * Set event payload.
     *
     * @param p Payload data.
     */
    public <T extends PayloadBase> void setPayload(T p) {
        payload = new Payload<T>(p);
    }

    /**
     * Get event payload.
     *
     * @return Payload data extending {@link PayloadBase}.
     */
    @SuppressWarnings("unchecked")
    public <T extends PayloadBase> T getPayload() {
        return (T)payload.getData();
    }

    /**
     * Return the type of payload data associated with this event.
     *
     * @return {@link Payload.PayloadType}
     */
    public Payload.PayloadType getPayloadType() {
        return payload.getType();
    }

    /**
     * Get unique event ID.
     *
     * @return {@link UUID} associated with event.
     */
    public UUID getEventId() {
        return eventId;
    }

    /**
     * Get event timestamp.
     *
     * @return Timestamp associated with event.
     */
    public DateTime getTimestamp() {
        return timestamp;
    }

    /**
     * Set event timestamp.
     *
     * @param t {@link DateTime} to associate with event.
     */
    public void setTimestamp(DateTime t) {
        timestamp = t;
    }

    /**
     * Return normalized data set.
     *
     * @return {@link Normalized} data associated with event.
     */
    public Normalized getNormalized() {
        return normalized;
    }
}
