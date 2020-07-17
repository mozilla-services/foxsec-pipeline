package com.mozilla.secops.parser.models.gcpvpcflow;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;

/** JSON model for GCP VPC flow events */
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GcpVpcFlow implements Serializable {
  private static final long serialVersionUID = 1L;

  private Integer bytesSent;
  private Connection connection;
  private Instance srcInstance;

  /** Connection details */
  @JsonIgnoreProperties(ignoreUnknown = true)
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class Connection implements Serializable {
    private static final long serialVersionUID = 1L;

    private String srcIp;
    private String destIp;
    private Integer srcPort;
    private Integer destPort;

    /**
     * Get source IP
     *
     * @return String
     */
    @JsonProperty("src_ip")
    public String getSrcIp() {
      return srcIp;
    }

    /**
     * Get destination IP
     *
     * @return String
     */
    @JsonProperty("dest_ip")
    public String getDestIp() {
      return destIp;
    }

    /**
     * Get source port
     *
     * @return Integer
     */
    @JsonProperty("src_port")
    public Integer getSrcPort() {
      return srcPort;
    }

    /**
     * Get destination port
     *
     * @return Integer
     */
    @JsonProperty("dest_port")
    public Integer getDestPort() {
      return destPort;
    }
  }

  /** Instance details */
  @JsonIgnoreProperties(ignoreUnknown = true)
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public static class Instance implements Serializable {
    private static final long serialVersionUID = 1L;

    private String vmName;

    /**
     * Get VM name
     *
     * @return String
     */
    @JsonProperty("vm_name")
    public String getVmName() {
      return vmName;
    }
  }

  /**
   * Get bytes sent
   *
   * @return Integer
   */
  @JsonProperty("bytes_sent")
  public Integer getBytesSent() {
    return bytesSent;
  }

  /**
   * Get connection data
   *
   * @return Connection
   */
  @JsonProperty("connection")
  public Connection getConnection() {
    return connection;
  }

  /**
   * Get source instance data
   *
   * @return Instance
   */
  @JsonProperty("src_instance")
  public Instance getSrcInstance() {
    return srcInstance;
  }
}
