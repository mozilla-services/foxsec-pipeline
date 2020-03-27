package com.mozilla.secops;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.crypto.RuntimeSecrets;
import com.mozilla.secops.state.DatastoreStateInterface;
import com.mozilla.secops.state.State;
import com.mozilla.secops.state.StateCursor;
import com.mozilla.secops.state.StateException;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.StringJoiner;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.beam.sdk.metrics.Counter;
import org.apache.beam.sdk.metrics.Metrics;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
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

  /** Custom metric name used to count iprepd violation submissions from write functions */
  public static final String VIOLATION_WRITES_METRIC = "iprepd_violation_writes";

  /** Namespace for custom metrics */
  public static final String METRICS_NAMESPACE = "IprepdIO";

  /** A reputation response from iprepd */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class ReputationValue {
    private String object;
    private String type;
    private Integer reputation;

    /**
     * Get object field
     *
     * @return String
     */
    @JsonProperty("object")
    public String getObject() {
      return object;
    }

    /**
     * Set object field
     *
     * @param object Object string
     */
    public void setObject(String object) {
      this.object = object;
    }

    /**
     * Get type
     *
     * @return String
     */
    @JsonProperty("type")
    public String getType() {
      return type;
    }

    /**
     * Set type value
     *
     * @param type Type string
     */
    public void setType(String type) {
      this.type = type;
    }

    /**
     * Get reputation value
     *
     * @return Integer
     */
    @JsonProperty("reputation")
    public Integer getReputation() {
      return reputation;
    }

    /**
     * Set reputation value
     *
     * @param reputation Reputation integer
     */
    public void setReputation(Integer reputation) {
      this.reputation = reputation;
    }
  }

  /**
   * Return a new reader for reading reputation from iprepd
   *
   * <p>Specification format: url|api key
   *
   * <p>Example: "https://iprepd.example.com|secretapikey"
   *
   * <p>The specification processor supports RuntimeSecrets, and may therefore also be a cloudkms://
   * URL or a GCS URL.
   *
   * @param iprepdSpec iprepd input specification
   * @param project GCP project name, only required if decrypting apiKey via cloudkms
   * @return Reader
   */
  public static Reader getReader(String iprepdSpec, String project) {
    return new Reader(iprepdSpec, project);
  }

  public static class Reader {
    private static final long serialVersionUID = 1L;
    private final String iprepdSpec;
    private final String project;
    private final Logger log;
    private final HttpClient httpClient;

    private static HashMap<String, String> decrypted = new HashMap<String, String>();
    private static ReentrantLock decryptedLock = new ReentrantLock();

    /**
     * Read a reputation
     *
     * @param type Type of object to make request for
     * @param value Object to make request for
     * @return Reputation integer value
     */
    public Integer getReputation(String type, String value) {
      HttpResponse resp;

      String buf = null;
      decryptedLock.lock();
      try {
        // See if we already have the URL and key information cached; if not we will do so
        // on first invocation and store it.
        buf = decrypted.get(iprepdSpec);
        if (buf == null) {
          try {
            buf = RuntimeSecrets.interpretSecret(iprepdSpec, project);
            decrypted.put(iprepdSpec, buf);
          } catch (IOException exc) {
            throw new RuntimeException(exc.getMessage());
          }
        }
      } finally {
        decryptedLock.unlock();
      }
      String[] parts = buf.split("\\|");
      if (parts.length != 2) {
        throw new RuntimeException("format of iprepd input specification was invalid");
      }
      String url = parts[0];
      String apiKey = parts[1];

      String reqPath = new StringJoiner("/").add(url).add("type").add(type).add(value).toString();
      HttpGet get;
      try {
        get = new HttpGet(reqPath);
      } catch (IllegalArgumentException exc) {
        log.error(exc.getMessage());
        return new Integer(100);
      }
      if (apiKey != null) {
        get.addHeader("Authorization", "APIKey " + apiKey);
      }
      try {
        resp = httpClient.execute(get);
      } catch (IOException exc) {
        log.error(exc.getMessage());
        return new Integer(100);
      }
      int sc = resp.getStatusLine().getStatusCode();
      if (sc == 404) {
        // Reputation not found, report 100
        return new Integer(100);
      }
      if (sc != 200) {
        log.error("GET from iprepd returned with status code {}", sc);
        return new Integer(100);
      }
      HttpEntity entity = resp.getEntity();
      if (entity == null) {
        log.error("200 response from iprepd contained no response entity");
        return new Integer(100);
      }

      ReputationValue rval = null;
      InputStream is = null;

      try {
        is = entity.getContent();
      } catch (IOException exc) {
        log.error(exc.getMessage());
        return new Integer(100);
      }

      if (is == null) {
        log.error("200 response from iprepd contained no response content");
        return new Integer(100);
      }

      try {
        rval = new ObjectMapper().readValue(is, ReputationValue.class);
      } catch (IOException exc) {
        log.error(exc.getMessage());
        return new Integer(100);
      } finally {
        try {
          is.close();
        } catch (IOException exc) {
          throw new RuntimeException(exc.getMessage());
        }
      }

      if (rval.getReputation() == null) {
        log.error("response from iprepd contained no reputation value");
        return new Integer(100);
      }

      return rval.getReputation();
    }

    /**
     * Create new iprepd reader
     *
     * @param iprepdSpec iprepd input specification
     * @param project GCP project name, only required if decrypting spec via cloudkms
     */
    public Reader(String iprepdSpec, String project) {
      log = LoggerFactory.getLogger(Reader.class);
      this.iprepdSpec = iprepdSpec;
      this.project = project;
      httpClient = HttpClientBuilder.create().build();
    }
  }

  /**
   * Return {@link PTransform} to emit violations to one or more instances of iprepd
   *
   * <p>Specification format: url|api key
   *
   * <p>Example: "https://iprepd.example.com|secretapikey"
   *
   * <p>The specification processor supports RuntimeSecrets, and may therefore also be a cloudkms://
   * URL or a GCS URL.
   *
   * @param iprepdSpecs String[] of iprepd input specifications
   * @param project GCP project name, only required if decrypting apiKey via cloudkms
   * @return IO transform
   */
  public static Write writeSpecs(String[] iprepdSpecs, String project) {
    return new Write(iprepdSpecs, project);
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
    private final String[] iprepdSpecs;
    private final String project;

    /**
     * Create new iprepd write transform
     *
     * @param iprepdSpecs String[] of iprepd input specifications
     * @param project GCP project name, can be null if no cloudkms is required for secrets
     */
    public Write(String[] iprepdSpecs, String project) {
      this.iprepdSpecs = iprepdSpecs;
      this.project = project;
    }

    /**
     * Get iprepd specs
     *
     * @return iprepd specs
     */
    public String[] getIprepdSpecs() {
      return iprepdSpecs;
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
    private String[] iprepdSpecs;
    private String project;

    /** Writer initial connection timeout */
    public final int WRITER_TIMEOUT_CONNECTION = 5000;

    /** Writer connection manager connection request timeout */
    public final int WRITER_TIMEOUT_CONNECTION_REQUEST = 5000;

    /** Writer socket timeout */
    public final int WRITER_TIMEOUT_SOCKET = 5000;

    private Counter violationWrites = Metrics.counter(METRICS_NAMESPACE, VIOLATION_WRITES_METRIC);

    private static HashMap<String, String> decrypted = new HashMap<String, String>();
    private static ReentrantLock decryptedLock = new ReentrantLock();

    public WriteFn(Write wTransform) {
      this.wTransform = wTransform;
    }

    @Setup
    public void setup() throws IOException {
      log = LoggerFactory.getLogger(WriteFn.class);
      log.info("creating new HTTP client for iprepd submission");
      RequestConfig rc =
          RequestConfig.custom()
              .setConnectTimeout(WRITER_TIMEOUT_CONNECTION)
              .setConnectionRequestTimeout(WRITER_TIMEOUT_CONNECTION_REQUEST)
              .setSocketTimeout(WRITER_TIMEOUT_SOCKET)
              .build();
      httpClient = HttpClientBuilder.create().setDefaultRequestConfig(rc).build();

      project = wTransform.getProject();
      iprepdSpecs = wTransform.getIprepdSpecs();

      decryptedLock.lock();
      try {
        for (String i : iprepdSpecs) {
          decrypted.put(i, RuntimeSecrets.interpretSecret(i, project));
        }
      } finally {
        decryptedLock.unlock();
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

      Violation[] vlist = Violation.fromAlert(a);
      if (vlist == null) {
        // No need to log here, it's possible this is not an alert relevant for iprepd escalation
        return;
      }
      for (Violation v : vlist) {
        String object = v.getObject();
        String type = v.getType();

        String violationJSON = v.toJSON();
        if (violationJSON == null) {
          log.error("violation serialization failed");
          return;
        }

        violationWrites.inc();
        for (String spec : iprepdSpecs) {
          decryptedLock.lock();
          String decr = null;
          try {
            decr = decrypted.get(spec);
          } finally {
            decryptedLock.unlock();
          }
          if (decr == null) {
            throw new RuntimeException("iprepd specification not found in translation map");
          }
          String[] parts = decr.split("\\|");
          String url = parts[0];
          String apiKey = parts[1];

          try {
            String reqPath;
            reqPath =
                new StringJoiner("/")
                    .add(url)
                    .add("violations")
                    .add("type")
                    .add(type)
                    .add(object)
                    .toString();
            StringEntity body = new StringEntity(violationJSON);

            log.info(
                "notify iprepd url {} object {} type {} violation {}",
                url,
                object,
                type,
                v.getViolation());
            HttpPut put = new HttpPut(reqPath);
            put.addHeader("Content-Type", "application/json");
            put.setEntity(body);

            if (apiKey != null) {
              put.addHeader("Authorization", "APIKey " + apiKey);
            }

            HttpResponse resp = httpClient.execute(put);
            log.info(
                "PUT to iprepd at {} for {} returned with status code {}",
                url,
                object,
                resp.getStatusLine().getStatusCode());
            put.reset();
          } catch (IOException exc) {
            log.error(exc.getMessage());
          } catch (IllegalArgumentException exc) {
            log.error(exc.getMessage());
          }
        }
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

  /** WhitelistedObject contains the metadata associated with a whitelisted objects. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  public static class WhitelistedObject {
    private String ip;
    private String obj;
    private String type;
    private DateTime expiresAt;
    private String createdBy;

    /**
     * Get IP string
     *
     * @return IP string
     */
    @JsonProperty("ip")
    public String getIp() {
      return ip;
    }

    /**
     * Set IP
     *
     * @param ip IP string
     */
    public void setIp(String ip) {
      this.ip = ip;
    }

    /**
     * Get object string
     *
     * @return object string
     */
    @JsonProperty("object")
    public String getObject() {
      return obj;
    }

    /**
     * Set object string
     *
     * @param obj object string
     */
    public void setObject(String obj) {
      this.obj = obj;
    }

    /**
     * Get type string
     *
     * @return type string
     */
    @JsonProperty("type")
    public String getType() {
      return type;
    }

    /**
     * Set type string
     *
     * @param type type string
     */
    public void setType(String type) {
      this.type = type;
    }

    /**
     * Get expires at
     *
     * @return DateTime
     */
    @JsonProperty("expires_at")
    public DateTime getExpiresAt() {
      return expiresAt;
    }

    /**
     * Set expires at
     *
     * @param expiresAt DateTime
     */
    public void setExpiresAt(DateTime expiresAt) {
      this.expiresAt = expiresAt;
    }

    /**
     * Get created by value
     *
     * @return Created by
     */
    @JsonProperty("created_by")
    public String getCreatedBy() {
      return createdBy;
    }

    /**
     * Set created by value
     *
     * @param createdBy Created by
     */
    public void setCreatedBy(String createdBy) {
      this.createdBy = createdBy;
    }
  }

  /** Legacy Kind for whitelisted IP entry in Datastore */
  public static final String legacyWhitelistedIpKind = "whitelisted_ip";

  /** Legacy Namespace for whitelisted IP in Datastore */
  public static final String legacyWhitelistedIpNamespace = "whitelisted_ip";

  /** Kind for whitelisted IP entry in Datastore */
  public static final String whitelistedIpKind = "ip";

  /** Kind for whitelisted email entry in Datastore */
  public static final String whitelistedEmailKind = "email";

  /** Namespace for whitelisted objects in Datastore */
  public static final String whitelistedObjectNamespace = "whitelisted_object";

  /**
   * Add whitelisted IP metadata if the IP address is whitelisted.
   *
   * @param ip IP address to check
   * @param a Alert to add metadata to
   * @throws IOException IOException
   */
  public static void addMetadataIfIpWhitelisted(String ip, Alert a) throws IOException {
    addMetadataIfObjectWhitelisted(ip, whitelistedIpKind, a, null);
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
   * @throws IOException IOException
   */
  public static void addMetadataIfIpWhitelisted(String ip, Alert a, String datastoreProject)
      throws IOException {
    addMetadataIfObjectWhitelisted(ip, whitelistedIpKind, a, datastoreProject);
  }

  /**
   * Add whitelisted metadata if the object is whitelisted.
   *
   * @param obj Object to check (usually an IP or email)
   * @param type Type of object (usually "ip" or "email")
   * @param a Alert to add metadata to
   * @throws IOException IOException
   */
  public static void addMetadataIfObjectWhitelisted(String obj, String type, Alert a)
      throws IOException {
    addMetadataIfObjectWhitelisted(obj, type, a, null);
  }

  /**
   * Add whitelisted metadata if the object is whitelisted.
   *
   * <p>This variant allows specification of a project ID, for cases where the datastore instance
   * lives in another GCP project.
   *
   * <p>If for some reason the whitelist state lookup fails, an {@link IOException} will be thrown.
   *
   * @param obj Object to check (usually an IP or email)
   * @param type Type of object (usually "ip" or "email")
   * @param a Alert to add metadata to
   * @param datastoreProject If Datastore is in another project, non-null project ID
   * @throws IOException IOException
   */
  public static void addMetadataIfObjectWhitelisted(
      String obj, String type, Alert a, String datastoreProject) throws IOException {
    if (obj == null || type == null || a == null) {
      return;
    }

    if (!type.equals(whitelistedIpKind) && !type.equals(whitelistedEmailKind)) {
      return;
    }

    State state;
    State legacyState;
    if (datastoreProject != null) {
      state =
          new State(
              new DatastoreStateInterface(type, whitelistedObjectNamespace, datastoreProject));
      legacyState =
          new State(
              new DatastoreStateInterface(
                  legacyWhitelistedIpKind, legacyWhitelistedIpNamespace, datastoreProject));
    } else {
      state = new State(new DatastoreStateInterface(type, whitelistedObjectNamespace));
      legacyState =
          new State(
              new DatastoreStateInterface(legacyWhitelistedIpKind, legacyWhitelistedIpNamespace));
    }

    Logger log = LoggerFactory.getLogger(IprepdIO.class);

    try {
      state.initialize();
      legacyState.initialize();
    } catch (StateException exc) {
      log.error("error initializing state: {}", exc.getMessage());
      throw new IOException(exc.getMessage());
    }

    StateCursor<WhitelistedObject> sc = null;
    StateCursor<WhitelistedObject> lsc = null;
    try {
      sc = state.newCursor(WhitelistedObject.class, false);
      WhitelistedObject wobj = sc.get(obj);
      if (wobj != null) {
        a.addMetadata(IPREPD_EXEMPT, "true");
        a.addMetadata(IPREPD_EXEMPT + "_created_by", wobj.getCreatedBy());
      } else {
        if (type.equals(whitelistedIpKind)) {
          lsc = legacyState.newCursor(WhitelistedObject.class, false);
          WhitelistedObject legacyWobj = lsc.get(obj);
          if (legacyWobj != null) {
            a.addMetadata(IPREPD_EXEMPT, "true");
            a.addMetadata(IPREPD_EXEMPT + "_created_by", legacyWobj.getCreatedBy());
          }
        }
      }
    } catch (StateException exc) {
      log.error("error getting whitelisted object: {}", exc.getMessage());
      throw new IOException(exc.getMessage());
    } finally {
      state.done();
      legacyState.done();
    }
  }
}
