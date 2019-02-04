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

  @Description(
      "Write violation notices to iprepd; specify URL, only applicable for HTTPRequest results")
  String getOutputIprepd();

  void setOutputIprepd(String value);

  @Description("With iprepd output; use API key for authentication (supports RuntimeSecrets)")
  String getOutputIprepdApikey();

  void setOutputIprepdApikey(String value);

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

  @Description("Use memcached state; hostname of memcached server")
  String getMemcachedHost();

  void setMemcachedHost(String value);

  @Description("Use memcached state; port of memcached server")
  @Default.Integer(11211)
  Integer getMemcachedPort();

  void setMemcachedPort(Integer value);

  @Description("Use memcached for state management")
  Boolean getMemcachedEnabled();

  void setMemcachedEnabled(Boolean value);

  @Description("Use datastore for state management")
  Boolean getDatastoreEnabled();

  void setDatastoreEnabled(Boolean value);

  public static PTransform<PCollection<String>, PDone> compositeOutput(OutputOptions o) {
    return CompositeOutput.withOptions(o);
  }
}
