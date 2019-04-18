package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.crypto.RuntimeSecrets;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateException;
import java.io.IOException;
import java.util.StringJoiner;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link IprepdIO} provides an IO transform for writing violation messages to iprepd */
public class IprepdIO {
  /** Metadata tag in an alert to indicate iprepd exemption */
  public static final String IPREPD_EXEMPT = "iprepd_exempt";

  /** Metadata tag in an alert to indicate recovery suppression */
  public static final String IPREPD_SUPPRESS_RECOVERY = "iprepd_suppress_recovery";

  /**
   * Return {@link PTransform} to emit violations to iprepd
   *
   * @param url URL for iprepd service
   * @param apiKey API key as specified in pipeline options
   * @param project GCP project name, only required if decrypting apiKey via cloudkms
   * @return IO transform
   */
  public static Write write(String url, String apiKey, String project) {
    String key;
    try {
      key = RuntimeSecrets.interpretSecret(apiKey, project);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
    return new Write(url, key, project);
  }

  /**
   * Write violation messages to iprepd based on submitted {@link Alert} JSON strings
   *
   * <p>For each JSON string processed, an attempt will be made to convert the {@link Alert} into a
   * {@link Violation}, for any successful conversion the resulting violation will be submitted to
   * iprepd as a violation message for the source address. Any input data that is not an {@link
   * Alert} that can be converted into a violation will be ignored.
   */
  public static class Write extends PTransform<PCollection<String>, PDone> {
    private static final long serialVersionUID = 1L;
    private final String url;
    private final String apiKey;
    private final String project;

    /**
     * Create new iprepd write transform
     *
     * @param url URL for iprepd daemon (e.g., http://iprepd.example.host)
     * @param apiKey Use API key for auth, should be formatted for {@link RuntimeSecrets}
     * @param project GCP project name, can be null if no cloudkms is required for secrets
     */
    public Write(String url, String apiKey, String project) {
      this.url = url;
      this.apiKey = apiKey;
      this.project = project;
    }

    /**
     * Get configured URL
     *
     * @return URL string
     */
    public String getURL() {
      return url;
    }

    /**
     * Get configured API key
     *
     * @return API key as specified in pipeline options
     */
    public String getApiKey() {
      return apiKey;
    }

    /**
     * Get project
     *
     * @return Project string
     */
    public String getProject() {
      return project;
    }

    @Override
    public PDone expand(PCollection<String> input) {
      input.apply(ParDo.of(new WriteFn(this)));
      return PDone.in(input.getPipeline());
    }
  }

  private static class WriteFn extends DoFn<String, Void> {
    private static final long serialVersionUID = 1L;

    private final Write wTransform;
    private Logger log;
    private HttpClient httpClient;
    private String apiKey;
    private String project;

    public WriteFn(Write wTransform) {
      this.wTransform = wTransform;
    }

    @Setup
    public void setup() throws IOException {
      log = LoggerFactory.getLogger(WriteFn.class);
      log.info("creating new HTTP client for iprepd submission");
      httpClient = HttpClientBuilder.create().build();

      project = wTransform.getProject();
      apiKey = wTransform.getApiKey();
      if (apiKey != null) {
        log.info("using iprepd apikey authentication");
      }
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      String el = c.element();

      // See if we can convert this incoming element into an alert and subsequently into a
      // violation, if this is successful we can escalate it to iprepd
      Alert a = Alert.fromJSON(el);
      if (a == null) {
        log.error("alert deserialization failed for {}", el);
        return;
      }

      String iprepdExempt = a.getMetadataValue(IPREPD_EXEMPT);
      if (iprepdExempt != null && iprepdExempt.equals("true")) {
        return;
      }

      Violation v = Violation.fromAlert(a);
      if (v == null) {
        // No need to log here, it's possible this is not an alert relavent for iprepd escalation
        return;
      }
      String sourceAddress = v.getSourceAddress();

      String violationJSON = v.toJSON();
      if (violationJSON == null) {
        log.error("violation serialization failed");
        return;
      }

      try {
        String reqPath =
            new StringJoiner("/")
                .add(wTransform.getURL())
                .add("violations")
                .add(sourceAddress)
                .toString();
        StringEntity body = new StringEntity(violationJSON);

        log.info("notify iprepd client {} violation {}", sourceAddress, v.getViolation());
        HttpPut put = new HttpPut(reqPath);
        put.addHeader("Content-Type", "application/json");
        put.setEntity(body);

        if (apiKey != null) {
          put.addHeader("Authorization", "APIKey " + apiKey);
        }

        HttpResponse resp = httpClient.execute(put);
        log.info(
            "PUT to iprepd for {} returned with status code {}",
            sourceAddress,
            resp.getStatusLine().getStatusCode());
        put.reset();
      } catch (IOException exc) {
        log.error(exc.getMessage());
      }
    }
  }

  /**
   * Add iprepd recovery suppression metadata to an alert
   *
   * @param value Seconds for recovery suppression
   * @param a Alert
   */
  public static void addMetadataSuppressRecovery(Integer value, Alert a) {
    a.addMetadata(IPREPD_SUPPRESS_RECOVERY, value.toString());
  }

  /** WhitelistedIp contains the metadata associated with a whitelisted ip. */
  public static class WhitelistedIp {
    private String ip;
    private DateTime expiresAt;
    private String createdBy;

    @JsonProperty("ip")
    public String getIp() {
      return ip;
    }

    @JsonProperty("expires_at")
    public DateTime getExpiresAt() {
      return expiresAt;
    }

    @JsonProperty("created_by")
    public String getCreatedBy() {
      return createdBy;
    }
  }

  private static final String whitelistedIpKind = "whitelisted_ip";
  private static final String whitelistedIpNamespace = "whitelisted_ip";

  /**
   * Add whitelisted IP metadata if the IP address is whitelisted.
   *
   * @param ip IP address to check
   * @param a Alert to add metadata to
   */
  public static void addMetadataIfWhitelisted(String ip, Alert a) throws IOException {
    addMetadataIfWhitelisted(ip, a, null);
  }

  /**
   * Add whitelisted IP metadata if the IP address is whitelisted.
   *
   * <p>This variant allows specification of a project ID, for cases where the datastore instance
   * lives in another GCP project.
   *
   * @param ip IP address to check
   * @param a Alert to add metadata to
   * @param datastoreProject If Datastore is in another project, non-null project ID
   */
  public static void addMetadataIfWhitelisted(String ip, Alert a, String datastoreProject)
      throws IOException {
    if (ip == null || a == null) {
      return;
    }

    State state;
    if (datastoreProject != null) {
      state =
          new State(
              new DatastoreStateInterface(
                  whitelistedIpKind, whitelistedIpNamespace, datastoreProject));
    } else {
      state = new State(new DatastoreStateInterface(whitelistedIpKind, whitelistedIpNamespace));
    }

    Logger log = LoggerFactory.getLogger(IprepdIO.class);

    try {
      state.initialize();
    } catch (StateException exc) {
      log.error("error initializing state: {}", exc.getMessage());
      throw new IOException(exc.getMessage());
    }

    try {
      WhitelistedIp wip = state.get(ip, WhitelistedIp.class);
      if (wip != null) {
        a.addMetadata(IPREPD_EXEMPT, "true");
        a.addMetadata(IPREPD_EXEMPT + "_created_by", wip.getCreatedBy());
      }
    } catch (StateException exc) {
      log.error("error getting whitelisted ip: {}", exc.getMessage());
      throw new IOException(exc.getMessage());
    } finally {
      state.done();
    }
  }
}
