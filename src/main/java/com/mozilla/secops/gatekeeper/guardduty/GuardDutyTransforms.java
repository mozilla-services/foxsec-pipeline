package com.mozilla.secops.gatekeeper.guardduty;

import com.mozilla.secops.parser.*;
import java.io.Serializable;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PDone;

public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

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
