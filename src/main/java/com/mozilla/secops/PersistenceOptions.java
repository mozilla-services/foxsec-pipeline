package com.mozilla.secops;

import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;

public interface PersistenceOptions extends PipelineOptions {
  @Description("Write payloads to BigQuery; BigQuery table specification")
  String getPersistenceBigQuery();

  void setPersistenceBigQuery(String value);
}
