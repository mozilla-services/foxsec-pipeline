package com.mozilla.secops.parser;

import java.io.Serializable;

/** Encapsulation for parsed payload data */
public class Payload<T extends PayloadBase> implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Type of payload data stored */
  public enum PayloadType {
    /** Google load balancer */
    GLB,
    /** GCP Event Threat Detection */
    ETD,
    /** AWS CloudTrail */
    CLOUDTRAIL,
    /** AWS GuardDuty */
    GUARDDUTY,
    /** OpenSSH */
    OPENSSH,
    /** Duopull */
    DUOPULL,
    /**
     * SecEvent
     *
     * <p>Deprecated, no longer in use
     */
    SECEVENT,
    /** GcpAudit */
    GCPAUDIT,
    /** Nginx */
    NGINX,
    /** BmoAudit */
    BMOAUDIT,
    /** IPrepdLog */
    IPREPD_LOG,
    /** FxA auth */
    FXAAUTH,
    /** FxA content */
    FXACONTENT,
    /** Apache Combined */
    APACHE_COMBINED,
    /** Taskcluster */
    TASKCLUSTER,
    /** AMO Docker */
    AMODOCKER,
    /** Alert */
    ALERT,
    /** Internal configuration tick */
    CFGTICK,
    /** Auth0 log event */
    AUTH0,
    /** Phabricator audit log */
    PHABRICATOR_AUDIT,
    /** Private Relay */
    PRIVATE_RELAY,
    /** GCP VPC flow logs */
    GCP_VPC_FLOW,
    /** Raw */
    RAW
  }

  private T data;

  /**
   * Construct new payload object of specified type
   *
   * @param d Object extending {@link PayloadBase}
   */
  public Payload(T d) {
    data = d;
  }

  /**
   * Get payload data
   *
   * @return Object extending {@link PayloadBase}
   */
  public T getData() {
    return data;
  }

  /**
   * Get payload type
   *
   * @return {@link PayloadType}
   */
  public PayloadType getType() {
    return data.getType();
  }
}
