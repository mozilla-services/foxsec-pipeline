package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.util.ArrayList;

/**
 * Represents a single identity
 */
public class Identity {
    private ArrayList<String> aliases;

    /**
     * Get username aliases for identity
     *
     * @return Aliases
     */
    @JsonProperty("aliases")
    public ArrayList<String> getAliases() {
        return aliases;
    }
}
