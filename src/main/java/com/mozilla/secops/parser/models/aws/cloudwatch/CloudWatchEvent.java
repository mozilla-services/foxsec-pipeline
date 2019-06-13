package com.mozilla.secops.parser.models.aws.cloudwatch;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * Describes the format of an AWS CloudWatch Event
 *
 * <p>See also
 * https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CloudWatchEvent implements Serializable {
  private static final long serialVersionUID = 1L;

  private String version;
  private String id;
  private String detailType;
  private String source;
  private String account;
  private String time;
  private String region;
  private ArrayList<String> resources;
  private JsonNode detail;

  /**
   * Get event message version
   *
   * @return String
   */
  @JsonProperty("version")
  public String getVersion() {
    return version;
  }

  /**
   * Get event id
   *
   * @return String
   */
  @JsonProperty("id")
  public String getId() {
    return id;
  }

  /**
   * Get event detail type, e.g. GuardDuty Finding, AWS Health Event, etc...
   *
   * <p>See also https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/EventTypes.html
   *
   * @return String source ip
   */
  @JsonProperty("detail-type")
  public String getDetailType() {
    return detailType;
  }

  /**
   * Get event source service, e.g. aws.guardduty, aws.ec2, etc...
   *
   * @return String
   */
  @JsonProperty("source")
  public String getSource() {
    return source;
  }

  /**
   * Get event AWS account id
   *
   * @return String
   */
  @JsonProperty("account")
  public String getAccount() {
    return account;
  }

  /**
   * Get event timestamp
   *
   * @return String
   */
  @JsonProperty("time")
  public String getTime() {
    return time;
  }

  /**
   * Get event AWS region
   *
   * @return String
   */
  @JsonProperty("region")
  public String getRegion() {
    return region;
  }

  /**
   * Get event resources, typically in the form of ARNs
   *
   * @return ArrayList<String>
   */
  @JsonProperty("resources")
  public ArrayList<String> getResources() {
    return resources;
  }

  /**
   * Get event detail
   *
   * <p>This is a JSON format payload which must be parsed further in accordance to the "source" or
   * "detail-type" of the CloudWatch Event
   *
   * @return JsonNode
   */
  @JsonProperty("detail")
  public JsonNode getDetail() {
    return detail;
  }

  public CloudWatchEvent() {}
}
