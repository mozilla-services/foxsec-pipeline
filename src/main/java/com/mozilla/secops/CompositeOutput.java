package com.mozilla.secops;

import com.google.api.services.bigquery.model.TableRow;
import com.google.gson.Gson;
import com.mozilla.secops.alert.AlertConfiguration;
import com.mozilla.secops.alert.AlertIO;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.bigquery.BigQueryIO;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

/**
 * {@link CompositeOutput} provides a standardized composite output transform for use in pipelines.
 */
public abstract class CompositeOutput {
  private CompositeOutput() {}

  /**
   * Return a new composite output transform that can be used as the final stage in a pipeline.
   *
   * <p>{@link OutputOptions} can be used to configure the output phase.
   *
   * @param options {@link OutputOptions} used to configure returned {@link PTransform}.
   * @return Configured {@link PTransform}
   */
  public static PTransform<PCollection<String>, PDone> withOptions(OutputOptions options) {
    final String outputFile = options.getOutputFile();
    final String outputBigQuery = options.getOutputBigQuery();
    final String outputIprepd = options.getOutputIprepd();
    final String outputIprepdApikey = options.getOutputIprepdApikey();
    final String project = options.getProject();

    AlertConfiguration alertcfg = new AlertConfiguration();
    alertcfg.setSmtpCredentials(options.getOutputAlertSmtpCredentials());
    alertcfg.setSmtpRelay(options.getOutputAlertSmtpRelay());
    alertcfg.setEmailCatchall(options.getOutputAlertEmailCatchall());
    alertcfg.setEmailFrom(options.getOutputAlertEmailFrom());
    alertcfg.setGcpProject(project);
    alertcfg.setSlackToken(options.getOutputAlertSlackToken());
    alertcfg.setSlackCatchall(options.getOutputAlertSlackCatchall());

    return new PTransform<PCollection<String>, PDone>() {
      private static final long serialVersionUID = 1L;

      @Override
      public PDone expand(PCollection<String> input) {
        if (outputFile != null) {
          input.apply(TextIO.write().to(outputFile));
        }
        if (outputBigQuery != null) {
          PCollection<TableRow> bqdata =
              input.apply(
                  ParDo.of(
                      new DoFn<String, TableRow>() {
                        private static final long serialVersionUID = 1L;

                        @ProcessElement
                        public void processElement(ProcessContext c) {
                          Gson g = new Gson();
                          TableRow r = g.fromJson(c.element(), TableRow.class);
                          c.output(r);
                        }
                      }));
          bqdata.apply(
              BigQueryIO.writeTableRows()
                  .to(outputBigQuery)
                  .withCreateDisposition(BigQueryIO.Write.CreateDisposition.CREATE_NEVER)
                  .withWriteDisposition(BigQueryIO.Write.WriteDisposition.WRITE_APPEND));
        }
        if (outputIprepd != null) {
          input.apply(IprepdIO.write(outputIprepd, outputIprepdApikey, project));
        }
        if (alertcfg.isConfigured()) {
          input.apply(AlertIO.write(alertcfg));
        }
        return PDone.in(input.getPipeline());
      }
    };
  }
}
