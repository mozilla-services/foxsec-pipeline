package com.mozilla.secops.customs;

import com.mozilla.secops.parser.Event;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Combine.CombineFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;

/**
 * Combines windowed key/value collections into a collection of {@link CustomsFeatures}
 *
 * <p>CustomsFeaturesCombiner is a {@link CombineFn} that will combine a windowed collection of
 * {@link KV} objects, where the key is an arbitrary string and the value is an event, into a
 * collection of {@link CustomsFeatures} objects.
 *
 * <p>For each key in the input collection, all events keyed with that key are combined and
 * processed together to extract features for the resulting output collection.
 *
 * <p>The key is a arbitrary string, for example a source IP address. In this case, the resulting
 * {@link CustomsFeatures} object will contain features extracted for all events associated with
 * that IP address.
 */
public class CustomsFeaturesCombiner
    extends PTransform<PCollection<KV<String, Event>>, PCollection<KV<String, CustomsFeatures>>> {
  private static final long serialVersionUID = 1L;

  /** {@link CombineFn} for creating collections of {@link CustomsFeatures} */
  public static class CustomsFeaturesCombineFn
      extends CombineFn<Event, CustomsFeatures, CustomsFeatures> {
    private static final long serialVersionUID = 1L;

    @Override
    public CustomsFeatures createAccumulator() {
      return new CustomsFeatures();
    }

    @Override
    public CustomsFeatures addInput(CustomsFeatures col, Event input) {
      col.addEvent(input);
      return col;
    }

    @Override
    public CustomsFeatures mergeAccumulators(Iterable<CustomsFeatures> cols) {
      boolean f = false;
      CustomsFeatures ret = null;
      for (CustomsFeatures i : cols) {
        if (!f) {
          ret = i;
          f = true;
          continue;
        }
        ret.merge(i);
      }
      return ret;
    }

    @Override
    public CustomsFeatures extractOutput(CustomsFeatures col) {
      return col;
    }

    @Override
    public CustomsFeatures defaultValue() {
      return new CustomsFeatures();
    }
  }

  @Override
  public PCollection<KV<String, CustomsFeatures>> expand(PCollection<KV<String, Event>> input) {
    return input.apply(
        Combine.<String, Event, CustomsFeatures>perKey(new CustomsFeaturesCombineFn()));
  }
}
