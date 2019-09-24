package com.mozilla.secops.input;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.InitialPositionInStream;
import com.mozilla.secops.crypto.RuntimeSecrets;
import java.io.IOException;
import java.io.Serializable;
import org.apache.beam.sdk.io.kinesis.KinesisIO;
import org.apache.beam.sdk.io.kinesis.KinesisRecord;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

/** Configuration for a single Kinesis input */
public class KinesisInput implements Serializable {
  private static final long serialVersionUID = 1L;

  private String streamName;
  private String region;
  private String id;
  private String secret;

  private void setStreamName(String streamName) {
    this.streamName = streamName;
  }

  private void setRegion(String region) {
    this.region = region;
  }

  private void setId(String id) {
    this.id = id;
  }

  private void setSecret(String secret) {
    this.secret = secret;
  }

  /**
   * Apply {@link KinesisIO} using configuration set in object
   *
   * <p>When executed, will apply the KinesisIO transform in addition to a ParDo which splits
   * individual elements by new line, returning raw strings read from the stream.
   *
   * @param PBegin Pipeline begin
   * @return Collection of strings
   */
  public PCollection<String> toCollection(PBegin begin) {
    return begin
        .apply(
            String.format("%s %s", streamName, region),
            KinesisIO.read()
                .withStreamName(streamName)
                .withInitialPositionInStream(InitialPositionInStream.LATEST)
                .withAWSClientsProvider(id, secret, Regions.fromName(region)))
        .apply(
            ParDo.of(
                new DoFn<KinesisRecord, String>() {
                  private static final long serialVersionUID = 1L;

                  @ProcessElement
                  public void processElement(ProcessContext c) {
                    // Assume for now our Kinesis record contains newline delimited
                    // elements. Split these up and send them individually.
                    //
                    // This may need to be configurable depending on the input
                    // stream at some point.
                    String[] e = new String(c.element().getDataAsBytes()).split("\\r?\\n");
                    for (String i : e) {
                      c.output(i);
                    }
                  }
                }));
  }

  /**
   * Parse Kinesis input specification into configuration
   *
   * <p>Specification format: <streamname>:<region>:<access id>:<access secret>
   *
   * <p>The specification processor supports RuntimeSecrets, and may therefore also be a cloudkms://
   * URL or a GCS URL.
   *
   * @param spec Input specification
   * @param project GCP project if specification is encrypted with RuntimeSecrets, null otherwise
   * @return {@link KinesisInput}
   */
  public static KinesisInput fromInputSpecifier(String spec, String project) {
    String buf;
    try {
      buf = RuntimeSecrets.interpretSecret(spec, project);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }
    String[] parts = buf.split(":");
    if (parts.length != 4) {
      throw new RuntimeException("format of kinesis input specification was invalid");
    }
    KinesisInput ret = new KinesisInput();
    ret.setStreamName(parts[0]);
    ret.setRegion(parts[3]);
    ret.setId(parts[1]);
    ret.setSecret(parts[2]);
    return ret;
  }
}
