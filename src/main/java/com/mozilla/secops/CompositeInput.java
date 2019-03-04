package com.mozilla.secops;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.InitialPositionInStream;
import com.mozilla.secops.crypto.RuntimeSecrets;
import java.io.IOException;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.io.kinesis.KinesisIO;
import org.apache.beam.sdk.io.kinesis.KinesisRecord;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * {@link CompositeInput} provides a standardized composite input transform for use in pipelines.
 */
public class CompositeInput extends PTransform<PBegin, PCollection<String>> {
  private static final long serialVersionUID = 1L;

  private final String[] fileInputs;
  private final String[] pubsubInputs;
  private final String[] kinesisInputs;
  private final String project;

  /**
   * Initialize new {@link CompositeInput} transform
   *
   * @param options Input options
   */
  public CompositeInput(InputOptions options) {
    fileInputs = options.getInputFile();
    pubsubInputs = options.getInputPubsub();
    kinesisInputs = options.getInputKinesis();
    project = options.getProject();
  }

  @Override
  public PCollection<String> expand(PBegin begin) {
    PCollectionList<String> inputList = PCollectionList.<String>empty(begin.getPipeline());

    if (fileInputs != null) {
      for (String i : fileInputs) {
        inputList = inputList.and(begin.apply(TextIO.read().from(i)));
      }
    }

    if (pubsubInputs != null) {
      for (String i : pubsubInputs) {
        inputList = inputList.and(begin.apply(PubsubIO.readStrings().fromTopic(i)));
      }
    }

    if (kinesisInputs != null) {
      for (String i : kinesisInputs) {
        String k = null;
        try {
          k = RuntimeSecrets.interpretSecret(i, project);
        } catch (IOException exc) {
          // XXX Just return null here for now which will result in a null pointer exception in the
          // pipeline, but this should also log the error.
          return null;
        }
        String[] parts = k.split(":");
        if (parts.length != 4) {
          return null;
        }
        inputList =
            inputList.and(
                begin
                    .apply(
                        KinesisIO.read()
                            .withStreamName(parts[0])
                            .withInitialPositionInStream(InitialPositionInStream.LATEST)
                            .withAWSClientsProvider(parts[1], parts[2], Regions.fromName(parts[3])))
                    .apply(
                        ParDo.of(
                            new DoFn<KinesisRecord, String>() {
                              private static final long serialVersionUID = 1L;

                              @ProcessElement
                              public void processElement(ProcessContext c) {
                                c.output(new String(c.element().getDataAsBytes()));
                              }
                            })));
      }
    }

    return inputList.apply(Flatten.<String>pCollections());
  }
}
