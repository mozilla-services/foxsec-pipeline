package com.mozilla.secops;

import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.crypto.RuntimeSecrets;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** {@link IprepdIO} provides an IO transform for writing violation messages to iprepd */
public class IprepdIO {
  /**
   * Return {@link PTransform} to emit violations to iprepd
   *
   * @param url URL for iprepd service
   * @param apiKey API key as specified in pipeline options
   * @param project GCP project name, only required if decrypting apiKey via cloudkms
   * @return IO transform
   */
  public static Write write(String url, String apiKey, String project) {
    return new Write(url, apiKey, project);
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
        apiKey = RuntimeSecrets.interpretSecret(apiKey, project);
      }
    }

    @ProcessElement
    public void processElement(ProcessContext c) {
      String el = c.element();

      // See if we can convert this incoming element into an alert and subsequently into a
      // violation, if this is successful we can escalate it to iprepd
      Alert a = Alert.fromJSON(el);
      if (a == null) {
        return;
      }

      Violation v = Violation.fromAlert(a);
      if (v == null) {
        return;
      }
      String sourceAddress = v.getSourceAddress();

      String violationJSON = v.toJSON();
      if (violationJSON == null) {
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
        log.warn(exc.getMessage());
      }
    }
  }
}
