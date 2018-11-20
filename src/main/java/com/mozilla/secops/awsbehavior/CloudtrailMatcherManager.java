package com.mozilla.secops.awsbehavior;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Translates a JSON document into EventFilter's
 */
public class CloudtrailMatcherManager {
    private ArrayList<CloudtrailMatcher> eventMatchers;

    public static CloudtrailMatcherManager loadFromResource(String resourcePath) throws IOException {
        InputStream in = CloudtrailMatcherManager.class.getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IOException("cloudtrail matcher manager resource not found");
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(in, CloudtrailMatcherManager.class);
    }

    @JsonProperty("event_matchers")
    public ArrayList<CloudtrailMatcher> getEventMatchers() {
        return eventMatchers;
    }

    /**
     * Create new empty {@link CloudtrailMatcherManager}
     */
    public CloudtrailMatcherManager() {
        eventMatchers = new ArrayList<CloudtrailMatcher>();
    }
}
