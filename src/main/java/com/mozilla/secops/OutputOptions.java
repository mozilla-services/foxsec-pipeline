package com.mozilla.secops;

import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PDone;
import org.apache.beam.sdk.values.PCollection;

public interface OutputOptions extends PipelineOptions {
    @Description("Write output to file; file path")
    String getOutputFile();
    void setOutputFile(String value);

    @Description("Write output to BigQuery; BigQuery table specification")
    String getOutputBigQuery();
    void setOutputBigQuery(String value);

    public static PTransform<PCollection<String>, PDone> compositeOutput(OutputOptions o) {
        return CompositeOutput.withOptions(o);
    }
}
