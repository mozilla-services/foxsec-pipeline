package com.mozilla.secops.input;

import java.util.HashMap;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;

/**
 * The input collection cache is used to optimize the graph for duplicate stream reads within the
 * {@link Input} class.
 */
public class InputCollectionCache {
  private HashMap<String, PCollection<String>> fileInputs;
  private HashMap<String, PCollection<String>> pubsubInputs;
  private HashMap<String, PCollection<String>> kinesisInputs;

  /**
   * Request file input
   *
   * @param begin Pipeline begin
   * @param name File input path
   * @return PCollection
   */
  public PCollection<String> fileInput(PBegin begin, String name) {
    if (fileInputs.containsKey(name)) {
      return fileInputs.get(name);
    }
    PCollection<String> ret = begin.apply(name, TextIO.read().from(name));
    fileInputs.put(name, ret);
    return ret;
  }

  /**
   * Request Pubsub input
   *
   * @param begin Pipeline begin
   * @param name Pubsub topic
   * @return PCollection
   */
  public PCollection<String> pubsubInput(PBegin begin, String name) {
    if (pubsubInputs.containsKey(name)) {
      return pubsubInputs.get(name);
    }
    PCollection<String> ret = begin.apply(name, PubsubIO.readStrings().fromTopic(name));
    pubsubInputs.put(name, ret);
    return ret;
  }

  /**
   * Request Kinesis input
   *
   * @param begin Pipeline begin
   * @param name Kinesis input specification
   * @param project Project name if CloudKMS decryption is required for specification
   * @return PCollection
   */
  public PCollection<String> kinesisInput(PBegin begin, String name, String project) {
    if (kinesisInputs.containsKey(name)) {
      return kinesisInputs.get(name);
    }
    KinesisInput k = KinesisInput.fromInputSpecifier(name, project);
    PCollection<String> ret = k.toCollection(begin);
    kinesisInputs.put(name, ret);
    return ret;
  }

  /** Initialize collection cache */
  public InputCollectionCache() {
    fileInputs = new HashMap<String, PCollection<String>>();
    pubsubInputs = new HashMap<String, PCollection<String>>();
    kinesisInputs = new HashMap<String, PCollection<String>>();
  }
}
