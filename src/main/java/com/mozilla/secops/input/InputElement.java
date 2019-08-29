package com.mozilla.secops.input;

import com.mozilla.secops.metrics.CfgTickGenerator;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import java.io.Serializable;
import java.util.ArrayList;
import org.apache.beam.sdk.io.TextIO;
import org.apache.beam.sdk.io.gcp.pubsub.PubsubIO;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * InputElement represents a set of input sources that will always result in a single output
 * collection.
 */
public class InputElement implements Serializable {
  private static final long serialVersionUID = 1L;

  private String name;

  private transient ArrayList<String> fileInputs;
  private transient ArrayList<String> pubsubInputs;
  private transient ArrayList<KinesisInput> kinesisInputs;

  private transient ParserCfg parserCfg;
  private transient EventFilter filter;

  private String cfgTickMessage;
  private Integer cfgTickInterval;
  private long cfgTickMax;

  /**
   * Get element name
   *
   * @return Element name
   */
  public String getName() {
    return name;
  }

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

  public PCollection<Event> expandElement(PBegin begin) {
    if (parserCfg == null) {
      throw new RuntimeException("no parser configured for element");
    }

    PCollection<String> col = expandElementRaw(begin);
    ParserDoFn fn = new ParserDoFn().withConfiguration(parserCfg);
    if (filter != null) {
      fn = fn.withInlineEventFilter(filter);
    }
    return col.apply("parse", ParDo.of(fn));
  }

  /**
   * Set the parser configuration to use with parsed reads
   *
   * <p>Specifies the parser configuration that will be used with the parser when the resulting
   * collection returned from the element is of type {@link Event}.
   *
   * @param parserCfg Parser configuration
   * @return this for chaining
   */
  public InputElement setParserConfiguration(ParserCfg parserCfg) {
    this.parserCfg = parserCfg;
    return this;
  }

  /**
   * Set event filter to use with parsed reads
   *
   * <p>A valid parser configuration must be installed prior to calling this method.
   *
   * @param filter {@link EventFilter}
   * @return this for chaining
   */
  public InputElement setEventFilter(EventFilter filter) {
    if (parserCfg == null) {
      throw new RuntimeException("parser must be configured to set an event filter");
    }
    this.filter = filter;
    return this;
  }

  /**
   * Set configuration ticks for input element
   *
   * @param cfgTickMessage JSON message string to use
   * @param cfgTickInterval Tick interval in seconds
   * @param cfgTickMax Maximum number of ticks to generate before exiting
   * @return this for chaining
   */
  public InputElement setConfigurationTicks(
      String cfgTickMessage, Integer cfgTickInterval, long cfgTickMax) {
    if (cfgTickMessage == null) {
      throw new RuntimeException("configuration ticks enabled but no message specified");
    }
    this.cfgTickMessage = cfgTickMessage;
    this.cfgTickInterval = cfgTickInterval;
    this.cfgTickMax = cfgTickMax;
    return this;
  }

  /**
   * Add a new file input
   *
   * @param input File input path
   * @return this for chaining
   */
  public InputElement addFileInput(String input) {
    fileInputs.add(input);
    return this;
  }

  /**
   * Add new Pubsub input
   *
   * @param input Pubsub topic
   * @return this for chaining
   */
  public InputElement addPubsubInput(String input) {
    pubsubInputs.add(input);
    return this;
  }

  /**
   * Add new Kinesis input
   *
   * @param input Kinesis input specification
   * @return this for chaining
   */
  public InputElement addKinesisInput(KinesisInput input) {
    kinesisInputs.add(input);
    return this;
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
