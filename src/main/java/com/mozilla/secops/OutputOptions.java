package com.mozilla.secops;

import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.extensions.gcp.options.GcpOptions;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.PDone;
import org.apache.beam.sdk.values.PCollection;

/**
 * Standard output options for pipelines, intended for use with the
 * {@link CompositeOutput} transform.
 */
public interface OutputOptions extends PipelineOptions, GcpOptions {
    @Description("Write output to file; file path")
    String getOutputFile();
    void setOutputFile(String value);

    @Description("Write output to BigQuery; BigQuery table specification")
    String getOutputBigQuery();
    void setOutputBigQuery(String value);

    @Description("Write violation notices to iprepd; specify URL, only applicable for HTTPRequest results")
    String getOutputIprepd();
    void setOutputIprepd(String value);

    @Description("With iprepd output; use API key for authentication (supports RuntimeSecrets)")
    String getOutputIprepdApikey();
    void setOutputIprepdApikey(String value);

    @Description("With alert email output; AWS credentials format id:secret (supports RuntimeSecrets)")
    String getOutputAlertSesCredentials();
    void setOutputAlertSesCredentials(String value);

    @Description("Global email catch-all; e-mail address to receive copy of alerts")
    String getOutputAlertEmailCatchall();
    void setOutputAlertEmailCatchall(String value);

    public static PTransform<PCollection<String>, PDone> compositeOutput(OutputOptions o) {
        return CompositeOutput.withOptions(o);
    }
}
