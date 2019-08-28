package com.mozilla.secops.input;

import com.mozilla.secops.metrics.CfgTickGenerator;
import java.util.ArrayList;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * InputElement represents a set of input sources that will always result in a single output
 * collection.
 */
public class InputElement {
  private String name;

  private ArrayList<String> fileInputs;
  private ArrayList<String> pubsubInputs;
  private ArrayList<KinesisInput> kinesisInputs;

  private String cfgTickMessage;
  private Integer cfgTickInterval;
  private long cfgTickMax;

  /**
   * Expand configured input types into a resulting collection of strings
   *
   * @param PBegin Pipeline begin
   */
  public PCollection<String> expandElementRaw(PBegin begin) {
    PCollectionList<String> list = PCollectionList.<String>empty(begin.getPipeline());

    if (cfgTickMessage != null) {
      list =
          list.and(begin.apply(new CfgTickGenerator(cfgTickMessage, cfgTickInterval, cfgTickMax)));
    }

    for (String i : fileInputs) {
      list = list.and(begin.apply(TextIO.read().from(i)));
    }
    for (String i : pubsubInputs) {
      list = list.and(begin.apply(PubsubIO.readStrings().fromTopic(i)));
    }
    for (KinesisInput i : kinesisInputs) {
      list = list.and(i.toCollection(begin));
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

    return list.apply(Flatten.<String>pCollections());
  }

  /**
   * Set configuration ticks for input element
   *
   * @param cfgTickMessage JSON message string to use
   * @param cfgTickInterval Tick interval in seconds
   * @param cfgTickMax Maximum number of ticks to generate before exiting
   */
  public void setConfigurationTicks(
      String cfgTickMessage, Integer cfgTickInterval, long cfgTickMax) {
    if (cfgTickMessage == null) {
      throw new RuntimeException("configuration ticks enabled but no message specified");
    }
    this.cfgTickMessage = cfgTickMessage;
    this.cfgTickInterval = cfgTickInterval;
    this.cfgTickMax = cfgTickMax;
  }

  /**
   * Add a new file input
   *
   * @param input File input path
   */
  public void addFileInput(String input) {
    fileInputs.add(input);
  }

  /**
   * Add new Pubsub input
   *
   * @param input Pubsub topic
   */
  public void addPubsubInput(String input) {
    pubsubInputs.add(input);
  }

  /**
   * Add new Kinesis input
   *
   * @param input Kinesis input specification
   */
  public void addKinesisInput(KinesisInput input) {
    kinesisInputs.add(input);
  }

  /**
   * Create new InputElement
   *
   * @param name Name to associate with element
   */
  public InputElement(String name) {
    this.name = name;

    fileInputs = new ArrayList<String>();
    pubsubInputs = new ArrayList<String>();
    kinesisInputs = new ArrayList<KinesisInput>();
  }
}
