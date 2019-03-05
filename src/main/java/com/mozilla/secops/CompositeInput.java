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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link CompositeInput} provides a standardized composite input transform for use in pipelines.
 */
public class CompositeInput extends PTransform<PBegin, PCollection<String>> {
  private static final long serialVersionUID = 1L;

  private final int MAX_KINESIS_RETRIES = 5;

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
    Logger log = LoggerFactory.getLogger(CompositeInput.class);

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
        int tries = 0;
        while (tries < MAX_KINESIS_RETRIES) {
          Boolean success = false;
          log.info("attempting kinesis input setup for {} in {}", parts[0], parts[3]);
          tries++;
          try {
            inputList =
                inputList.and(
                    begin
                        .apply(
                            KinesisIO.read()
                                .withStreamName(parts[0])
                                .withInitialPositionInStream(InitialPositionInStream.LATEST)
                                .withAWSClientsProvider(
                                    parts[1], parts[2], Regions.fromName(parts[3])))
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
                                    // stream
                                    // at some point.
                                    String[] e =
                                        new String(c.element().getDataAsBytes()).split("\\r?\\n");
                                    for (String i : e) {
                                      c.output(i);
                                    }
                                  }
                                })));
            success = true;
          } catch (Exception exc) {
            if (tries == MAX_KINESIS_RETRIES) {
              return null;
            }
            log.info("sleeping to retry kinesis input: {}", exc.getMessage());
            try {
              Thread.sleep(7500);
            } catch (InterruptedException iexc) {
              // pass
            }
          }
          if (success) {
            break;
          }
        }
      }
    }

    return inputList.apply(Flatten.<String>pCollections());
  }
}
