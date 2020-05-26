package com.mozilla.secops.alert;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Splitter;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link AlertMeta} is metadata associated with an {@link Alert} */
public class AlertMeta implements Serializable {
  private static final long serialVersionUID = 1L;

  private static final Logger log = LoggerFactory.getLogger(AlertMeta.class);

  private String key;
  private String value;

  private static final Splitter META_VALUE_SPLITTER = Splitter.on(",").trimResults();

  /**
   * Join a list of values for a specific metadata key
   *
   * @param key Key
   * @param input List of values
   * @return String
   */
  public static String joinListValues(Key key, List<String> input) throws IOException {
    if (!key.getValueType().equals(Key.ValueType.LIST)) {
      String buf = String.format("key %s for join is not of type list", key.getKey());
      log.error(buf);
      throw new IOException(buf);
    }
    return String.join(", ", input);
  }

  /**
   * Split a list of values for a specific metadata key
   *
   * @param key Key
   * @param input String
   * @return List
   */
  public static List<String> splitListValues(Key key, String input) throws IOException {
    if (!key.getValueType().equals(Key.ValueType.LIST)) {
      String buf = String.format("key %s for split is not of type list", key.getKey());
      log.error(buf);
      throw new IOException(buf);
    }
    return META_VALUE_SPLITTER.splitToList(input);
  }

  /**
   * Generic alert metadata value validator
   *
   * <p>Will only verify the value is non-null and not empty.
   */
  private static class AlertMetadataValidator {
    /**
     * Validate single value format
     *
     * @param value Value for validation
     * @return True if value is formatted correctly for key
     */
    protected boolean validateValue(String key, String value) {
      if (value == null || value.isEmpty()) {
        log.error("value for key {} is invalid: {}", key, value);
        return false;
      }
      return true;
    }

    /**
     * Run validation on the value being set within a key
     *
     * @param value Value for validation
     * @return True if value is formatted correctly for key
     */
    public boolean validate(Key key, String value) {
      if (key.getValueType().equals(Key.ValueType.LIST)) {
        if (value == null) {
          log.error("null value passed for list type key {}", key.getKey());
          return false;
        }
        try {
          return splitListValues(key, value).stream().allMatch(i -> validateValue(key.getKey(), i));
        } catch (IOException exc) {
          // Should never happen at this point
          throw new RuntimeException("list type assertion during list split");
        }
      } else {
        return validateValue(key.getKey(), value);
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
    ADDON_FROM_API("addon_from_api"),
    ADDON_GUID("addon_guid"),
    ADDON_ID("addon_id"),
    ADDON_SIZE("addon_size"),
    ADDON_USER_ID("addon_user_id"),
    ADDON_VERSION("addon_version"),
    ALERT_HANDLING_SEVERITY("alert_handling_severity"),
    ALERT_NOTIFICATION_TYPE("alert_notification_type"),
    ALERT_SUBCATEGORY_FIELD("category"),
    ALERTIO_IGNORE_EVENT("alertio_ignore_event"),
    AUTH_ALERT_TYPE("auth_alert_type"),
    AWS_ACCOUNT_ID("aws_account_id"),
    AWS_ACCOUNT_NAME("aws_account_name"),
    AWS_REGION("aws_region"),
    COUNT("count"),
    DESCRIPTION("description"),
    DOC_LINK("doc_link"),
    EMAIL("email", true, new AlertMetadataValidator(), null, ValueType.LIST),
    EMAIL_CONTACT("email_contact"),
    EMAIL_SIMILAR("email_similar", true, new AlertMetadataValidator(), null, ValueType.LIST),
    END("end"),
    ENDPOINT("endpoint"),
    ENDPOINT_PATTERN("endpoint_pattern"),
    ENTRY_KEY("entry_key"),
    ERROR_COUNT("error_count"),
    ERROR_THRESHOLD("error_threshold"),
    ESCALATE_TO("escalate_to"),
    EVENT_TIMESTAMP("event_timestamp"),
    EVENT_TIMESTAMP_SOURCE_LOCAL("event_timestamp_source_local"),
    FINDING_ID("finding_id"),
    FINDING_TYPE("finding_type"),
    IDENTITY_KEY("identity_key"),
    IDENTITY_UNTRACKED("identity_untracked"),
    INDICATOR("indicator"),
    IPREPD_EXEMPT("iprepd_exempt"),
    IPREPD_EXEMPT_CREATED_BY("iprepd_exempt_created_by"),
    IPREPD_SUPPRESS_RECOVERY("iprepd_suppress_recovery"),
    KM_DISTANCE("km_distance"),
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
    SOURCEADDRESSES("sourceaddresses", true, new AlertMetadataValidator(), null, ValueType.LIST),
    START("start"),
    STATE_ACTION_TYPE("state_action_type"),
    STATUS("status"),
    TECHNIQUE("technique"),
    TEMPLATE_NAME_EMAIL("template_name_email"),
    TEMPLATE_NAME_SLACK("template_name_slack"),
    TEMPLATE_NAME_SLACK_CATCHALL("template_name_slack_catchall"),
    THRESHOLD("threshold"),
    THRESHOLD_MODIFIER("threshold_modifier"),
    TIME_DELTA_SECONDS("time_delta_seconds"),
    TOTAL_ADDRESS_COUNT("total_address_count"),
    TOTAL_ALERT_COUNT("total_alert_count"),
    UID("uid", true),
    USERAGENT("useragent"),
    USERNAME("username"),
    URL_TO_FINDING("url_to_finding"),
    WINDOW_TIMESTAMP("window_timestamp"),
    WHITELISTED_ENTRY_CREATED_BY("whitelisted_entry_created_by"),
    SOURCEADDRESS(
        "sourceaddress",
        true,
        new AlertMetadataValidator(),
        new AssociatedKeyLinkage[] {
          new AssociatedKeyLinkage(SOURCEADDRESS_CITY, AssociatedKey.CITY),
          new AssociatedKeyLinkage(SOURCEADDRESS_COUNTRY, AssociatedKey.COUNTRY),
          new AssociatedKeyLinkage(SOURCEADDRESS_ISP, AssociatedKey.ISP),
          new AssociatedKeyLinkage(SOURCEADDRESS_ASN, AssociatedKey.ASN),
          new AssociatedKeyLinkage(SOURCEADDRESS_AS_ORG, AssociatedKey.AS_ORG)
        },
        ValueType.SINGLE),
    SOURCEADDRESS_PREVIOUS(
        "sourceaddress_previous",
        true,
        new AlertMetadataValidator(),
        new AssociatedKeyLinkage[] {
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_CITY, AssociatedKey.CITY),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_COUNTRY, AssociatedKey.COUNTRY),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_ISP, AssociatedKey.ISP),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_ASN, AssociatedKey.ASN),
          new AssociatedKeyLinkage(SOURCEADDRESS_PREVIOUS_AS_ORG, AssociatedKey.AS_ORG)
        },
        ValueType.SINGLE);

    /** Storage formats for value fields */
    public enum ValueType {
      SINGLE,
      LIST
    }

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
    private ValueType valueType;

    /**
     * Return the string that will be used as the metadata key
     *
     * @return String
     */
    public String getKey() {
      return key;
    }

    /**
     * Return if key is considered sensitive
     *
     * @return boolean
     */
    public boolean getIsSensitive() {
      return isSensitive;
    }

    /**
     * Get value field type
     *
     * @return ValueType
     */
    public ValueType getValueType() {
      return valueType;
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
     * @param value Value
     * @return True if value was formatted correctly for key
     */
    public boolean validate(String value) {
      return validator.validate(this, value);
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
        AssociatedKeyLinkage[] links,
        ValueType valueType) {
      if (links == null) {
        links = new AssociatedKeyLinkage[] {};
      }
      this.key = key;
      this.isSensitive = isSensitive;
      this.validator = validator;
      this.valueType = valueType;
      associatedKeys = links;
    }

    /**
     * Initialize new key
     *
     * @param key String to use for key
     */
    Key(String key) {
      this(key, false, new AlertMetadataValidator(), null, ValueType.SINGLE);
    }

    /**
     * Initialize new key
     *
     * @param key String to use for key
     * @param links Associated key linkages
     */
    Key(String key, AssociatedKeyLinkage[] links) {
      this(key, false, new AlertMetadataValidator(), links, ValueType.SINGLE);
    }

    /**
     * Initialize new key
     *
     * @param key String to use for key
     * @param isSensitive True if metadata is considered to contain sensitive information
     */
    Key(String key, boolean isSensitive) {
      this(key, isSensitive, new AlertMetadataValidator(), null, ValueType.SINGLE);
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

  /**
   * Convert metadata to various formats
   *
   * <p>This main function can be used to export metadata keys in golang format, and to export a
   * BigQuery view query that is suitable for metrics usage.
   *
   * @param args Arguments
   */
  public static void main(String[] args) throws IOException {
    if (args[0].equals("gometa")) {
      BufferedWriter w = new BufferedWriter(new FileWriter(args[1]));
      w.write("package common\n\n// This file is automatically generated.\n\nconst (\n");
      for (Key k : Key.values()) {
        w.write(String.format("META_%s = \"%s\"\n", k.name(), k.getKey()));
      }
      w.write(")\n");
      w.close();
    } else if (args[0].equals("metricsview")) {
      BufferedWriter w = new BufferedWriter(new FileWriter(args[1]));
      ArrayList<String> sFields = new ArrayList<>();
      for (Key k : Key.values()) {
        if (k.getIsSensitive()) {
          sFields.add("'" + k.getKey() + "'");
        }
      }
      w.write(
          String.format(
              "SELECT "
                  + "id, timestamp, severity, category, ARRAY(\nSELECT AS STRUCT key, "
                  + "value FROM UNNEST(metadata) WHERE\nkey NOT IN (%s)\n) AS metadata\n"
                  + "FROM <<table>>\n",
              String.join(", ", sFields)));
      w.close();
    }
  }
}
