package com.mozilla.secops;

import org.apache.beam.sdk.extensions.gcp.options.GcpOptions;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Validation;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/**
 * Standard output options for pipelines, intended for use with the {@link CompositeOutput}
 * transform.
 */
public interface OutputOptions extends PipelineOptions, GcpOptions {
  @Description("Write output to file; file path")
  String getOutputFile();

  void setOutputFile(String value);

  @Description("Write output to BigQuery; BigQuery table specification")
  String getOutputBigQuery();

  void setOutputBigQuery(String value);

  @Description("Write output to Pubsub; Pubsub topic")
  String getOutputPubsub();

  void setOutputPubsub(String value);

  @Description("Write output to SQS; SQS queue specification (supports RuntimeSecrets)")
  String getOutputSqs();

  void setOutputSqs(String value);

  @Description(
      "Write violation notices to iprepd; specify URL, only applicable for HTTPRequest results")
  String getOutputIprepd();

  void setOutputIprepd(String value);

  @Description("With iprepd output; use API key for authentication (supports RuntimeSecrets)")
  String getOutputIprepdApikey();

  void setOutputIprepdApikey(String value);

  @Description("Enable use of whitelisted ips saved in datastore; requires deployment in GCP")
  @Default.Boolean(false)
  Boolean getOutputIprepdEnableDatastoreWhitelist();

  void setOutputIprepdEnableDatastoreWhitelist(Boolean value);

  @Description("Use whitelisting datastore in specified project; project ID")
  String getOutputIprepdDatastoreWhitelistProject();

  void setOutputIprepdDatastoreWhitelistProject(String value);

  @Description(
      "With alert email output; SMTP credentials format id:secret (supports RuntimeSecrets)")
  String getOutputAlertSmtpCredentials();

  void setOutputAlertSmtpCredentials(String value);

  @Description("SMTP relay for email output; relay hostname")
  String getOutputAlertSmtpRelay();

  void setOutputAlertSmtpRelay(String value);

  @Description("Email from address; FROM address for email alerting")
  String getOutputAlertEmailFrom();

  void setOutputAlertEmailFrom(String value);

  @Description("Global email catch-all; e-mail address to receive copy of alerts")
  String getOutputAlertEmailCatchall();

  void setOutputAlertEmailCatchall(String value);

  @Description("With alert slack output; Slack token (supports RuntimeSecrets)")
  String getOutputAlertSlackToken();

  void setOutputAlertSlackToken(String value);

  @Description("With alert slack output; channel to receive copy of alerts")
  String getOutputAlertSlackCatchall();

  void setOutputAlertSlackCatchall(String value);

  @Description("Monitored resource indicator to include in any alert metadata")
  @Validation.Required
  String getMonitoredResourceIndicator();

  void setMonitoredResourceIndicator(String value);

  @Description("Use memcached alert state; hostname of memcached server")
  String getAlertStateMemcachedHost();

  void setAlertStateMemcachedHost(String value);

  @Description("Use memcached alert state; port of memcached server")
  @Default.Integer(11211)
  Integer getAlertStateMemcachedPort();

  void setAlertStateMemcachedPort(Integer value);

  @Description("Use datastore alert state; namespace for entities")
  String getAlertStateDatastoreNamespace();

  void setAlertStateDatastoreNamespace(String value);

  @Description("Use datastore alert state; kind for entities")
  String getAlertStateDatastoreKind();

  void setAlertStateDatastoreKind(String value);

  @Description("GCS path to alert templates; for example: gs://prod-alerts/templates")
  String getOutputAlertGcsTemplateBasePath();

  void setOutputAlertGcsTemplateBasePath(String value);

  public static PTransform<PCollection<String>, PDone> compositeOutput(OutputOptions o) {
    return CompositeOutput.withOptions(o);
  }
}
