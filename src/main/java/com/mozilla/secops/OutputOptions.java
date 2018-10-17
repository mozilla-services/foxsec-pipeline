package com.mozilla.secops;

import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PDone;
import org.apache.beam.sdk.values.PCollection;

/**
 * Standard output options for pipelines, intended for use with the
 * {@link CompositeOutput} transform.
 */
public interface OutputOptions extends PipelineOptions {
    @Description("Write output to file; file path")
    String getOutputFile();
    void setOutputFile(String value);

    @Description("Write output to BigQuery; BigQuery table specification")
    String getOutputBigQuery();
    void setOutputBigQuery(String value);

    @Description("Write violation notices to iprepd; specify URL, only applicable for HTTPRequest results")
    String getOutputIprepd();
    void setOutputIprepd(String value);

    public static PTransform<PCollection<String>, PDone> compositeOutput(OutputOptions o) {
        return CompositeOutput.withOptions(o);
    }
}
