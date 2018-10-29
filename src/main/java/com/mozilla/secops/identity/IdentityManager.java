package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.InputStream;
import java.io.IOException;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

/**
 * {@link IdentityManager} supports translations from values such as user names
 * to a global identifier for a user
 */
public class IdentityManager {
    private Map<String, Identity> identities;

    /**
     * Load identity manager configuration from a resource file
     *
     * @param resourcePath Resource path to load JSON file from
     * @return {@link IdentityManager}
     */
    public static IdentityManager loadFromResource(String resourcePath) throws IOException {
        InputStream in = IdentityManager.class.getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IOException("identity manager resource not found");
        }
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(in, IdentityManager.class);
    }

    /**
     * Get all known identities
     *
     * @return Map of identities, where key is global standardized name
     */
    @JsonProperty("identities")
    public Map<String, Identity> getIdentities() {
        return identities;
    }

    /**
     * Get specific identity
     *
     * @param identifier Global identifier to return {@link Identity} for
     * @return Identity, null if not found
     */
    public Identity getIdentity(String identifier) {
        return identities.get(identifier);
    }

    /**
     * Given supplied alias, return any matching global identity
     *
     * @param username Username to search for
     * @return Resolved global identity string
     */
    public String lookupAlias(String username) {
        for (Map.Entry<String, Identity> entry : identities.entrySet()) {
            Identity ival = entry.getValue();
            for (String alias : ival.getAliases()) {
                if (alias.equals(username)) {
                    return entry.getKey();
                }
            }
        }
        return null;
    }

    /**
     * Create new empty {@link IdentityManager}
     */
    public IdentityManager() {
        identities = new HashMap<String, Identity>();
    }
}
