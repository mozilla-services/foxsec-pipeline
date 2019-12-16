package com.mozilla.secops;

import org.apache.beam.sdk.extensions.gcp.options.GcpOptions;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubOptions;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;

/** Standard input options for pipelines. */
public interface InputOptions extends PipelineOptions, PubsubOptions, GcpOptions {
  @Description("Use event timestamps on output in parser DoFn")
  @Default.Boolean(false)
  Boolean getUseEventTimestamp();

  void setUseEventTimestamp(Boolean value);

  @Description(
      "Only inspect Stackdriver events generated for specified project identifier in parser DoFn")
  String getStackdriverProjectFilter();

  void setStackdriverProjectFilter(String value);

  @Description(
      "Only inspect Stackdriver events that have the provided labels in parser DoFn; key:value")
  String[] getStackdriverLabelFilters();

  void setStackdriverLabelFilters(String[] value);

  @Description(
      "If true, the parser will assume no Mozlog encapsulated messages are present (increased performance)")
  @Default.Boolean(false)
  Boolean getDisableMozlogStrip();

  void setDisableMozlogStrip(Boolean value);

  @Description(
      "If true, the parser will assume no Cloudwatch encapsulated messages are present (increased performance)")
  @Default.Boolean(false)
  Boolean getDisableCloudwatchStrip();

  void setDisableCloudwatchStrip(Boolean value);

  @Description(
    "If true, the parser will assume no CloudwatchLog encapsulated messages are present (increased performance)")
@Default.Boolean(false)
Boolean getDisableCloudwatchLogStrip();

void setDisableCloudwatchLogStrip(Boolean value);

  @Description("Read from Pubsub (multiple allowed); Pubsub topic")
  String[] getInputPubsub();

  void setInputPubsub(String[] value);

  @Description("Read from file (multiple allowed); File path")
  String[] getInputFile();

  void setInputFile(String[] value);

  @Description(
      "Read from Kinesis (multiple allowed); stream:key:secret:region (supports RuntimeSecrets)")
  String[] getInputKinesis();

  void setInputKinesis(String[] value);

  @Description("Path to load Maxmind City database; resource path, gcs path")
  String getMaxmindCityDbPath();

  void setMaxmindCityDbPath(String value);

  @Description("Path to load Maxmind ISP database; resource path, gcs path")
  String getMaxmindIspDbPath();

  void setMaxmindIspDbPath(String value);

  @Description("Enable XFF address selector; comma delimited list of trusted CIDR format subnets")
  String getXffAddressSelector();

  void setXffAddressSelector(String value);

  @Description("Specify identity manager configuration location; resource path, gcs path")
  String getIdentityManagerPath();

  void setIdentityManagerPath(String value);

  @Description("Install parser fast matcher; substring")
  String getParserFastMatcher();

  void setParserFastMatcher(String value);

  @Description("Configuration tick interval, 0 to disable; seconds")
  @Default.Integer(0)
  Integer getGenerateConfigurationTicksInterval();

  void setGenerateConfigurationTicksInterval(Integer value);

  @Description("Maximum number of configuration ticks to generate, -1 for forever; long")
  @Default.Long(-1)
  Long getGenerateConfigurationTicksMaximum();

  void setGenerateConfigurationTicksMaximum(Long value);

  @Description("Read reputation from iprepd; specify URL and API Key (supports RuntimeSecrets).")
  String getInputIprepd();

  void setInputIprepd(String value);

  @Description(
      "Max allowable timestamp difference, events with timestamp older than value in seconds will "
          + "be dropped; integer")
  Integer getMaxAllowableTimestampDifference();

  void setMaxAllowableTimestampDifference(Integer value);

  @Description("Maxmind Account Id for using Minfraud (supports RuntimeSecrets).")
  String getMaxmindAccountId();

  void setMaxmindAccountId(String value);

  @Description("Maxmind License Key for using Minfraud (supports RuntimeSecrets).")
  String getMaxmindLicenseKey();

  void setMaxmindLicenseKey(String value);
}
