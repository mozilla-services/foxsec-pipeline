package com.mozilla.secops.identity;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.GcsUtil;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link IdentityManager} supports translations from values such as user names to a global
 * identifier
 *
 * <p>In addition to username identity translation, this class can also handle translations from
 * values such as AWS account IDs to a more description account name.
 */
public class IdentityManager {
  private Map<String, Identity> identities;
  private Map<String, String> awsAccountMap;
  private Notify defaultNotification;

  /** Default identity manager resource path */
  public static final String DEFAULT_RESOURCE_PATH = "/identitymanager.json";

  /**
   * Load identity manager configuration from a resource file
   *
   * @param path Path to load JSON file from, resource path or GCS URL
   * @return {@link IdentityManager}
   */
  public static IdentityManager load(String path) throws IOException {
    InputStream in;
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = IdentityManager.class.getResourceAsStream(path);
    }
    if (in == null) {
      throw new IOException("identity manager resource not found");
    }
    ObjectMapper mapper = new ObjectMapper();
    return mapper.readValue(in, IdentityManager.class);
  }

  /**
   * Load identity manager configuration from default resource location
   *
   * @return {@link IdentityManager}
   */
  public static IdentityManager load() throws IOException {
    return load(DEFAULT_RESOURCE_PATH);
  }

  /**
   * Get AWS account map
   *
   * @return Map of AWS account identifiers to descriptive names
   */
  @JsonProperty("aws_account_map")
  public Map<String, String> getAwsAccountMap() {
    return awsAccountMap;
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
   * Get default notification configuration
   *
   * @return Default notification configuration as {@link Notify}
   */
  @JsonProperty("default_notify")
  public Notify getDefaultNotification() {
    return defaultNotification;
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
    // If the username matches a global identity value, just return that directly
    if (identities.get(username) != null) {
      return username;
    }

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

  /** Create new empty {@link IdentityManager} */
  public IdentityManager() {
    identities = new HashMap<String, Identity>();
    awsAccountMap = new HashMap<String, String>();
  }
}
