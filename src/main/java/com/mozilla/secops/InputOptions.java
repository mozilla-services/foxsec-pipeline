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
}
