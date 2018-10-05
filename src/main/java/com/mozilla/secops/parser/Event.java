package com.mozilla.secops.parser;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import java.io.Serializable;
import java.util.UUID;

public class Event implements Serializable {
    private static final long serialVersionUID = 1L;

    private Payload<? extends PayloadBase> payload;
    private final UUID eventId;
    private DateTime timestamp;
    private Normalized normalized;

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

    public <T extends PayloadBase> void setPayload(T p) {
        payload = new Payload<T>(p);
    }

    @SuppressWarnings("unchecked")
    public <T extends PayloadBase> T getPayload() {
        return (T)payload.getData();
    }

    public Payload.PayloadType getPayloadType() {
        return payload.getType();
    }

    public UUID getEventId() {
        return eventId;
    }

    public DateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(DateTime t) {
        timestamp = t;
    }

    public Normalized getNormalized() {
        return normalized;
    }
}
