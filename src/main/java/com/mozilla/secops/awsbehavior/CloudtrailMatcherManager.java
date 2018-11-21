package com.mozilla.secops.awsbehavior;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Loads a JSON document and converts it
 * into a list of {@link CloudtrailMatcher}s
 */
public class CloudtrailMatcherManager {
    private ArrayList<CloudtrailMatcher> eventMatchers;

    /**
     * Load cloudtrail matcher manager configuration from a resource file
     *
     * @param resourcePath Resource path to load JSON file from
     * @return {@link CloudtrailMatcherManager}
     */
    public static CloudtrailMatcherManager loadFromResource(String resourcePath) throws IOException {
        InputStream in = CloudtrailMatcherManager.class.getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IOException("cloudtrail matcher manager resource not found");
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(in, CloudtrailMatcherManager.class);
    }

    /**
     * Returns parsed {@link CloudtrailMatcher}s
     *
     * @return {@link ArrayList} of {@link CloudtrailMatcher}
     */
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
