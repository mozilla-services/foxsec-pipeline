package com.mozilla.secops;

import org.apache.beam.sdk.extensions.gcp.options.GcpOptions;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubOptions;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Validation;

/** Standard input options for pipelines. */
public interface InputOptions extends PipelineOptions, PubsubOptions, GcpOptions {
  @Description("Type of --input; must be one of [pubsub, file]")
  @Default.Enum("file")
  InputType getInputType();

  void setInputType(InputType value);

  @Description("Input to read from (multiple allowed); file path, Pubsub topic")
  @Validation.Required
  String[] getInput();

  void setInput(String[] value);

  @Description("Path to load Maxmind database; resource path, gcs path")
  String getMaxmindDbPath();

  void setMaxmindDbPath(String value);
}
