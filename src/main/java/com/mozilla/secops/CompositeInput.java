package com.mozilla.secops;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.kinesis.clientlibrary.lib.worker.InitialPositionInStream;
import com.mozilla.secops.crypto.RuntimeSecrets;
import com.mozilla.secops.metrics.CfgTickGenerator;
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

  private final String[] fileInputs;
  private final String[] pubsubInputs;
  private final String[] kinesisInputs;
  private final String project;
  private final Integer cfgTicksInterval;
  private final String cfgTickMessage;
  private final long cfgTicksMax;

  /**
   * Initialize new {@link CompositeInput} transform
   *
   * <p>The cfgTickMessage parameter if non-null should be a string that has been generated using
   * {@link com.mozilla.secops.metrics.CfgTickBuilder}.
   *
   * @param options Input options
   * @param cfgTickMessage If configuration ticks are enabled, the message to emit
   */
  public CompositeInput(InputOptions options, String cfgTickMessage) {
    fileInputs = options.getInputFile();
    pubsubInputs = options.getInputPubsub();
    kinesisInputs = options.getInputKinesis();
    project = options.getProject();
    cfgTicksInterval = options.getGenerateConfigurationTicksInterval();
    cfgTicksMax = options.getGenerateConfigurationTicksMaximum();
    this.cfgTickMessage = cfgTickMessage;
  }

  /**
   * Initialize new {@link CompositeInput} transform
   *
   * @param options Input options
   */
  public CompositeInput(InputOptions options) {
    this(options, null);
  }

  @Override
  public PCollection<String> expand(PBegin begin) {
    Logger log = LoggerFactory.getLogger(CompositeInput.class);

    PCollectionList<String> inputList = PCollectionList.<String>empty(begin.getPipeline());

    if (cfgTicksInterval > 0) {
      if (cfgTickMessage == null) {
        throw new RuntimeException("configuration ticks enabled but no message specified");
      }
      inputList =
          inputList.and(
              begin.apply(new CfgTickGenerator(cfgTickMessage, cfgTicksInterval, cfgTicksMax)));
    }

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
          throw new RuntimeException(exc.getMessage());
        }
        String[] parts = k.split(":");
        if (parts.length != 4) {
          throw new RuntimeException("format of kinesis input specification was invalid");
        }
        log.info("attempting kinesis input setup for {} in {}", parts[0], parts[3]);
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
                                // Assume for now our Kinesis record contains newline delimited
                                // elements. Split these up and send them individually.
                                //
                                // This may need to be configurable depending on the input
                                // stream at some point.
                                String[] e =
                                    new String(c.element().getDataAsBytes()).split("\\r?\\n");
                                for (String i : e) {
                                  c.output(i);
                                }
                              }
                            })));
        try {
          // XXX Pause for a moment here for cases where we are configuring multiple Kinesis streams
          // that might exist in the same account; since setup calls DescribeStream it is possible
          // to end up hitting rate limits here.
          //
          // Note this seems like it can also happen after initial configuration once the stream
          // starts being read, but KinesisIO does not handle the transient error.
          //
          // This needs more investigation.
          Thread.sleep(1000);
        } catch (InterruptedException exc) {
          // pass
        }
      }
    }

    return inputList.apply(Flatten.<String>pCollections());
  }
}
