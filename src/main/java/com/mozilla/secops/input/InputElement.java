package com.mozilla.secops.input;

import static com.fasterxml.jackson.annotation.JsonInclude.Include;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.mozilla.secops.InputOptions;
import com.mozilla.secops.metrics.CfgTickGenerator;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.EventFilter;
import com.mozilla.secops.parser.ParserCfg;
import com.mozilla.secops.parser.ParserDoFn;
import java.io.Serializable;
import java.util.ArrayList;
import org.apache.beam.sdk.transforms.Flatten;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.PBegin;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionList;

/**
 * InputElement represents a set of input sources that will always result in a single output
 * collection.
 */
@JsonInclude(Include.NON_EMPTY)
public class InputElement implements Serializable {
  private static final long serialVersionUID = 1L;

  private String name;

  private transient Input parent;

  private transient PTransform<PBegin, PCollection<String>> wiredStream;

  private transient ArrayList<String> fileInputs;
  private transient ArrayList<String> pubsubInputs;
  private transient ArrayList<String> kinesisInputs;

  private transient ParserCfg parserCfg;
  private transient EventFilter filter;

  private String cfgTickMessage;
  private Integer cfgTickInterval;
  private long cfgTickMax;

  /**
   * Return an {@link InputElement} given pipeline options
   *
   * <p>This can be used to configure an input element using settings present in InputOptions.
   *
   * @param name Name to associate with element
   * @param options Input options
   * @param cfgTickMessage Configuration tick message, null if not enabled
   * @return New element
   */
  public static InputElement fromPipelineOptions(
      String name, InputOptions options, String cfgTickMessage) {
    InputElement element = new InputElement(name);

    if (options.getGenerateConfigurationTicksInterval() > 0) {
      element.setConfigurationTicks(
          cfgTickMessage,
          options.getGenerateConfigurationTicksInterval(),
          options.getGenerateConfigurationTicksMaximum());
    }

    if (options.getInputFile() != null) {
      for (String buf : options.getInputFile()) {
        element.addFileInput(buf);
      }
    }

    if (options.getInputPubsub() != null) {
      for (String buf : options.getInputPubsub()) {
        element.addPubsubInput(buf);
      }
    }

    if (options.getInputKinesis() != null) {
      for (String buf : options.getInputKinesis()) {
        element.addKinesisInput(buf);
      }
    }
    return element;
  }

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
   * @param project GCP project, set if using RuntimeSecrets
   */
  public PCollection<String> expandElementRaw(PBegin begin, String project) {
    PCollectionList<String> list = PCollectionList.<String>empty(begin.getPipeline());

    if (cfgTickMessage != null) {
      list =
          list.and(
              begin.apply(
                  String.format("%s generate cfgtick", name),
                  new CfgTickGenerator(cfgTickMessage, cfgTickInterval, cfgTickMax)));
    }

    if (wiredStream != null) {
      list = list.and(begin.apply(wiredStream));
    }

    for (String i : fileInputs) {
      list = list.and(parent.getCache().fileInput(begin, i));
    }
    for (String i : pubsubInputs) {
      list = list.and(parent.getCache().pubsubInput(begin, i));
    }
    for (String i : kinesisInputs) {
      list = list.and(parent.getCache().kinesisInput(begin, i, project));
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

    return list.apply(
        String.format("%s flatten input components", name), Flatten.<String>pCollections());
  }

  /**
   * Expand configured input types into a resulting collection of parsed events
   *
   * @param PBegin Pipeline begin
   * @param project GCP project, set if using RuntimeSecrets
   */
  public PCollection<Event> expandElement(PBegin begin, String project) {
    if (parserCfg == null) {
      throw new RuntimeException("no parser configured for element");
    }

    PCollection<String> col = expandElementRaw(begin, project);
    ParserDoFn fn = new ParserDoFn().withConfiguration(parserCfg);
    if (filter != null) {
      fn = fn.withInlineEventFilter(filter);
    }
    return col.apply(String.format("%s parse", name), ParDo.of(fn));
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
  @JsonProperty("parser_configuration")
  public InputElement setParserConfiguration(ParserCfg parserCfg) {
    this.parserCfg = parserCfg;
    return this;
  }

  /**
   * Get parser configuration
   *
   * @return Parser configuration or null if unset
   */
  public ParserCfg getParserConfiguration() {
    return parserCfg;
  }

  /**
   * Set event filter to use with parsed reads
   *
   * <p>A valid parser configuration must be installed prior to calling this method.
   *
   * @param filter {@link EventFilter}
   * @return this for chaining
   */
  @JsonProperty("filter")
  public InputElement setEventFilter(EventFilter filter) {
    this.filter = filter;
    return this;
  }

  /**
   * Get event filter
   *
   * @return Configured event filter or null
   */
  public EventFilter getEventFilter() {
    return filter;
  }

  /**
   * Set configuration ticks for input element
   *
   * <p>Note that although {@link InputElement} is serializable to/from JSON, configuration ticks
   * are specifically excluded from this. If an input element is initialized from JSON and
   * configuration ticks are desired, these must be set manually.
   *
   * @param cfgTickMessage JSON message string to use
   * @param cfgTickInterval Tick interval in seconds
   * @param cfgTickMax Maximum number of ticks to generate before exiting
   * @return this for chaining
   */
  @JsonIgnore
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
   * Add wired stream
   *
   * @param s Wired input transform
   * @return this for chaining
   */
  public InputElement addWiredStream(PTransform<PBegin, PCollection<String>> s) {
    wiredStream = s;
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
   * Set file inputs
   *
   * @param fileInputs File inputs
   */
  @JsonProperty("file_inputs")
  public void setFileInputs(ArrayList<String> fileInputs) {
    this.fileInputs = fileInputs;
  }

  /**
   * Get file inputs
   *
   * @return File inputs
   */
  public ArrayList<String> getFileInputs() {
    return fileInputs;
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
   * Set Pubsub inputs
   *
   * @param pubsubInputs Pubsub inputs
   */
  @JsonProperty("pubsub_inputs")
  public void setPubsubInputs(ArrayList<String> pubsubInputs) {
    this.pubsubInputs = pubsubInputs;
  }

  /**
   * Get Pubsub inputs
   *
   * @return Pubsub inputs
   */
  public ArrayList<String> getPubsubInputs() {
    return pubsubInputs;
  }

  /**
   * Add new Kinesis input
   *
   * @param input Kinesis input specification
   * @return this for chaining
   */
  public InputElement addKinesisInput(String input) {
    kinesisInputs.add(input);
    return this;
  }

  /**
   * Set Kinesis inputs
   *
   * @param kinesisInputs Kinesis inputs
   */
  @JsonProperty("kinesis_inputs")
  public void setKinesisInputs(ArrayList<String> kinesisInputs) {
    this.kinesisInputs = kinesisInputs;
  }

  /**
   * Get Kinesis inputs
   *
   * @return Kinesis inputs
   */
  public ArrayList<String> getKinesisInputs() {
    return kinesisInputs;
  }

  /**
   * Set parent {@link Input} object
   *
   * <p>This is an internal method and should not generally be called directly.
   *
   * @param parent Parent input object
   */
  @JsonIgnore
  public void setParentInput(Input parent) {
    this.parent = parent;
  }

  /**
   * Create new InputElement
   *
   * @param name Name to associate with element
   */
  @JsonCreator
  public InputElement(@JsonProperty("name") String name) {
    this.name = name;

    fileInputs = new ArrayList<String>();
    pubsubInputs = new ArrayList<String>();
    kinesisInputs = new ArrayList<String>();
  }
}
