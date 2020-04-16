package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** {@link AlertMeta} is metadata associated with an {@link Alert} */
public class AlertMeta implements Serializable {
  private static final long serialVersionUID = 1L;

  private String key;
  private String value;

  /**
   * Generic alert metadata value validator
   *
   * <p>Will only verify the value is non-null and not empty.
   */
  private static class AlertMetadataValidator {
    /**
     * Validate value
     *
     * @param value Value for validation
     * @throws IllegalArgumentException IllegalArgumentException
     */
    public void validate(String key, String value) {
      if (value == null || value.isEmpty()) {
        throw new IllegalArgumentException(String.format("invalid metadata value for %s", key));
      }
    }
  }

  private static class AssociatedKeyLinkage {
    public Key link;
    public Key.AssociatedKey associatedKey;

    AssociatedKeyLinkage(Key link, Key.AssociatedKey associatedKey) {
      this.link = link;
      this.associatedKey = associatedKey;
    }
  }

  /** Keys that may be used for alert metadata */
  public enum Key {
    ADDON_FILENAME("addon_filename"),
    ADDON_GUID("addon_guid"),
    ADDON_ID("addon_id"),
    ADDON_SIZE("addon_size"),
    ADDON_VERSION("addon_version"),
    ALERT_HANDLING_SEVERITY("alert_handling_severity"),
    ALERT_NOTIFICATION_TYPE("alert_notification_type"),
    ALERT_SUBCATEGORY_FIELD("category"),
    ALERTIO_IGNORE_EVENT("alertio_ignore_event"),
    AUTH_ALERT_TYPE("auth_alert_type"),
    AWS_ACCOUNT_ID("aws_account_id"),
    AWS_ACCOUNT_NAME("aws_account_name"),
    AWS_REGION("aws_region"),
    AWS_SERVICE("aws_service"),
    CATEGORY("category"),
    COUNT("count"),
    DESCRIPTION("description"),
    DOC_LINK("doc_link"),
    DOMAIN("domain"),
    DOMAIN_NAME("domain_name"),
    EMAIL("email"),
    EMAIL_CONTACT("email_contact"),
    EMAIL_SIMILAR("email_similar"),
    END("end"),
    ENDPOINT("endpoint"),
    ENDPOINT_PATTERN("endpoint_pattern"),
    ENTRY_KEY("entry_key"),
    ERROR_COUNT("error_count"),
    ERROR_THRESHOLD("error_threshold"),
    ESCALATE_TO("escalate_to"),
    EVENT_TIMESTAMP("event_timestamp"),
    EVENT_TIMESTAMP_SOURCE_LOCAL("event_timestamp_source_local"),
    EVIDENCE_INSERT_ID("evidence_insert_id"),
    EVIDENCE_TIMESTAMP("evidence_timestamp"),
    FINDING_ID("finding_id"),
    FINDING_TYPE("finding_type"),
    IDENTITY_KEY("identity_key"),
    IDENTITY_UNTRACKED("identity_untracked"),
    INDICATOR("indicator"),
    IPREPD_EXEMPT("iprepd_exempt"),
    IPREPD_EXEMPT_CREATED_BY("iprepd_exempt_created_by"),
    IPREPD_SUPPRESS_RECOVERY("iprepd_suppress_recovery"),
    KM_DISTANCE("km_distance"),
    LOCATION("location"),
    MASKED_SUMMARY("masked_summary"),
    MATCHED_METADATA_KEY("matched_metadata_key"),
    MATCHED_METADATA_VALUE("matched_metadata_value"),
    MATCHED_OBJECT("matched_object"),
    MATCHED_TYPE("matched_type"),
    MEAN("mean"),
    METHOD("method"),
    MONITORED_RESOURCE("monitored_resource"),
    NOTIFY_EMAIL_DIRECT("notify_email_direct"),
    NOTIFY_MERGE("notify_merge"),
    NOTIFY_MERGED_COUNT("notify_merged_count"),
    NOTIFY_SLACK_DIRECT("notify_slack_direct"),
    OBJECT("object"),
    PROJECT_ID("project_id"),
    PROJECT_NUMBER("project_number"),
    PROVIDER("provider"),
    REQUEST_THRESHOLD("request_threshold"),
    RESOURCE("resource"),
    RESTRICTED_VALUE("restricted_value"),
    RULE_NAME("rule_name"),
    SOURCE_ALERT("source_alert"),
    SOURCEADDRESS_AS_ORG("sourceaddress_as_org"),
    SOURCEADDRESS_ASN("sourceaddress_asn"),
    SOURCEADDRESS_CITY("sourceaddress_city"),
    SOURCEADDRESS_COUNTRY("sourceaddress_country"),
    SOURCEADDRESS_IS_ANONYMOUS("sourceaddress_is_anonymous"),
    SOURCEADDRESS_IS_ANONYMOUS_VPN("sourceaddress_is_anonymous_vpn"),
    SOURCEADDRESS_IS_HOSTING_PROVIDER("sourceaddress_is_hosting_provider"),
    SOURCEADDRESS_IS_LEGITIMATE_PROXY("sourceaddress_is_legitimate_proxy"),
    SOURCEADDRESS_IS_PUBLIC_PROXY("sourceaddress_is_public_proxy"),
    SOURCEADDRESS_IS_TOR_EXIT_NODE("sourceaddress_is_tor_exit_node"),
    SOURCEADDRESS_ISP("sourceaddress_isp"),
    SOURCEADDRESS_PREVIOUS_AS_ORG("sourceaddress_previous_as_org"),
    SOURCEADDRESS_PREVIOUS_ASN("sourceaddress_previous_asn"),
    SOURCEADDRESS_PREVIOUS_CITY("sourceaddress_previous_city"),
    SOURCEADDRESS_PREVIOUS_COUNTRY("sourceaddress_previous_country"),
    SOURCEADDRESS_PREVIOUS_ISP("sourceaddress_previous_isp"),
    SOURCEADDRESS_RISKSCORE("sourceaddress_riskscore"),
    SOURCEADDRESS_TIMEZONE("sourceaddress_timezone"),
    SOURCEADDRESSES("sourceaddresses"),
    START("start"),
    STATE_ACTION_TYPE("state_action_type"),
    STATUS("status"),
    SUBNETWORK_ID("subnetwork_id"),
    SUBNETWORK_NAME("subnetwork_name"),
    TAG_NAME("tag_name"),
    TECHNIQUE("technique"),
    TEMPLATE_NAME_EMAIL("template_name_email"),
    TEMPLATE_NAME_SLACK("template_name_slack"),
    THRESHOLD("threshold"),
    THRESHOLD_MODIFIER("threshold_modifier"),
    TIME_DELTA_SECONDS("time_delta_seconds"),
    TOTAL_ADDRESS_COUNT("total_address_count"),
    TOTAL_ALERT_COUNT("total_alert_count"),
    UID("uid"),
    USER("user"),
    USER_NAME("user_name"),
    USERAGENT("useragent"),
    USERNAME("username"),
    URL_TO_FINDING("url_to_finding"),
    WINDOW_TIMESTAMP("window_timestamp"),
    WHITELISTED_ENTRY_CREATED_BY("whitelisted_entry_created_by"),
    SOURCEADDRESS(
        "sourceaddress",
        new AssociatedKeyLinkage[] {
          new AssociatedKeyLinkage(SOURCEADDRESS_CITY, AssociatedKey.CITY),
          new AssociatedKeyLinkage(SOURCEADDRESS_COUNTRY, AssociatedKey.COUNTRY),
          new AssociatedKeyLinkage(SOURCEADDRESS_ISP, AssociatedKey.ISP),
          new AssociatedKeyLinkage(SOURCEADDRESS_ASN, AssociatedKey.ASN),
          new AssociatedKeyLinkage(SOURCEADDRESS_AS_ORG, AssociatedKey.AS_ORG)
        }),
    SOURCEADDRESS_PREVIOUS(
        "sourceaddress_previous",
        new AssociatedKeyLinkage[] {
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_CITY, AssociatedKey.CITY),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_COUNTRY, AssociatedKey.COUNTRY),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_ISP, AssociatedKey.ISP),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_ASN, AssociatedKey.ASN),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_AS_ORG, AssociatedKey.AS_ORG)
        });

    /**
     * Associated key identifiers
     *
     * <p>In some cases, a particular metadata key is associated with others; for example a GeoIP
     * city/country value that is associated with a particular source address field. These
     * identifiers can be used to establish this linkage in the parent key.
     */
    public enum AssociatedKey {
      CITY,
      COUNTRY,
      ISP,
      ASN,
      AS_ORG
    }

    private String key;
    private boolean isSensitive;
    private AlertMetadataValidator validator;
    private AssociatedKeyLinkage[] associatedKeys;

    /**
     * Return the string that will be used as the metadata key
     *
     * @return String
     */
    public String getKey() {
      return key;
    }

    /**
     * Obtain given associated key type
     *
     * <p>If a key associated has been established for this key of a given type, return the
     * associated key. Returns null if no association has been established.
     *
     * @param association Association type
     * @return Key or null if not found
     */
    public Key getAssociatedKey(AssociatedKey association) {
      for (AssociatedKeyLinkage i : associatedKeys) {
        if (i.associatedKey.equals(association)) {
          return i.link;
        }
      }
      return null;
    }

    /**
     * Validate the format of a value to be used for this key
     *
     * <p>This method behaves as an assertion and will throw {@link IllegalArgumentException} if the
     * value is invalid.
     *
     * @param value Value
     */
    public void validate(String value) {
      validator.validate(key, value);
    }

    /**
     * Initialize new Key
     *
     * @param key String to use for key
     * @param isSensitive True if metadata is considered to contain sensitive information
     * @param validator The validator to use for the value of this key
     * @param links Establish as parent key with provided linkages, null for none
     */
    Key(
        String key,
        boolean isSensitive,
        AlertMetadataValidator validator,
        AssociatedKeyLinkage[] links) {
      if (links == null) {
        links = new AssociatedKeyLinkage[] {};
      }
      this.key = key;
      this.isSensitive = isSensitive;
      this.validator = validator;
      associatedKeys = links;
    }

    /**
     * Initialize new key
     *
     * @param key String to use for key
     */
    Key(String key) {
      this(key, false, new AlertMetadataValidator(), null);
    }

    Key(String key, AssociatedKeyLinkage[] links) {
      this(key, false, new AlertMetadataValidator(), links);
    }
  }

  /** Keys that are known to contain IP address values */
  public static final Key[] IPADDRESS_KEYS = {Key.SOURCEADDRESS, Key.SOURCEADDRESS_PREVIOUS};

  /**
   * Get metadata key
   *
   * @return Key string
   */
  @JsonProperty("key")
  public String getKey() {
    return key;
  }

  /**
   * Set metadata value
   *
   * @param value Value to set
   */
  @JsonProperty("value")
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * Get metadata value
   *
   * @return Value string
   */
  public String getValue() {
    return value;
  }

  /**
   * Create new {@link AlertMeta}
   *
   * @param key Metadata key
   * @param value Metadata value
   */
  @JsonCreator
  public AlertMeta(@JsonProperty("key") String key, @JsonProperty("value") String value) {
    this.key = key;
    this.value = value;
  }
}
