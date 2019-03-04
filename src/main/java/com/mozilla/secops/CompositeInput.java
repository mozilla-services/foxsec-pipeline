package com.mozilla.secops;

import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
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

  /**
   * Initialize new {@link CompositeInput} transform
   *
   * @param options Input options
   */
  public CompositeInput(InputOptions options) {
    fileInputs = options.getInputFile();
    pubsubInputs = options.getInputPubsub();
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

    return inputList.apply(Flatten.<String>pCollections());
  }
}
