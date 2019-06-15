package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.transforms.*;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /**
   * A grouping transform that groups Events by their inner GuardDuty Finding's source AWS account
   * ID
   */
  public static class ByAccount
      extends PTransform<PCollection<Event>, PCollection<KV<String, Event>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Event>> expand(PCollection<Event> input) {
      return input.apply(
          WithKeys.of(
              new SerializableFunction<Event, String>() {
                private static final long serialVersionUID = 1L;

                @Override
                public String apply(Event input) {
                  GuardDuty gde = input.getPayload();
                  return gde.getFinding().getAccountId();
                }
              }));
    }
  }

  /**
   * A grouping transform that groups Events by their inner GuardDuty Finding's source AWS region
   */
  public static class ByRegion
      extends PTransform<PCollection<Event>, PCollection<KV<String, Event>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Event>> expand(PCollection<Event> input) {
      return input.apply(
          WithKeys.of(
              new SerializableFunction<Event, String>() {
                private static final long serialVersionUID = 1L;

                @Override
                public String apply(Event input) {
                  GuardDuty gde = input.getPayload();
                  return gde.getFinding().getRegion();
                }
              }));
    }
  }

  /** A grouping transform that groups Events by their inner GuardDuty Finding's Type */
  public static class ByType
      extends PTransform<PCollection<Event>, PCollection<KV<String, Event>>> {
    private static final long serialVersionUID = 1L;

    @Override
    public PCollection<KV<String, Event>> expand(PCollection<Event> input) {
      return input.apply(
          WithKeys.of(
              new SerializableFunction<Event, String>() {
                private static final long serialVersionUID = 1L;

                @Override
                public String apply(Event input) {
                  GuardDuty gde = input.getPayload();
                  return gde.getFinding().getType();
                }
              }));
    }
  }

  /** An output transform that simply prints the string Key in the KV given */
  public static class PrintKeys extends PTransform<PCollection<KV<String, Event>>, PDone> {
    private static final long serialVersionUID = 1L;

    @Override
    public PDone expand(PCollection<KV<String, Event>> input) {
      input.apply(
          ParDo.of(
              new DoFn<KV<String, Event>, Void>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  System.out.println(c.element().getKey());
                }
              }));
      return PDone.in(input.getPipeline());
    }
  }

  /** transform to print out a {@link PCollection} containing strings */
  private static class PrintString extends PTransform<PCollection<String>, PDone> {
    private static final long serialVersionUID = 1L;

    @Override
    public PDone expand(PCollection<String> input) {
      input.apply(
          ParDo.of(
              new DoFn<String, Void>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  System.out.println(c.element());
                }
              }));
      return PDone.in(input.getPipeline());
    }
  }
}
