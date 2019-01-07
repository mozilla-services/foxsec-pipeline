package com.mozilla.secops;

import static org.junit.Assert.assertEquals;

import java.util.Collection;
import org.apache.beam.sdk.testing.PAssert;
import org.apache.beam.sdk.testing.TestPipeline;
import org.apache.beam.sdk.transforms.Create;
import org.apache.beam.sdk.values.PCollection;
import org.junit.Rule;
import org.junit.Test;

public class TestStats {
  public TestStats() {}

  @Rule public final transient TestPipeline pipeline = TestPipeline.create();

  @Test
  public void StatsTest() throws Exception {
    PCollection<Long> input = pipeline.apply(Create.of(5L, 5L, 5L, 5L, 5L, 5L, 5L, 5L, 5L, 10L));
    PCollection<Stats.StatsOutput> results = input.apply(new Stats());

    PAssert.that(results)
        .satisfies(
            x -> {
              Stats.StatsOutput s =
                  ((Collection<Stats.StatsOutput>) x).toArray(new Stats.StatsOutput[0])[0];
              assertEquals(5.5, (double) s.getMean(), 0.1);
              assertEquals(2.25, (double) s.getPopulationVariance(), 0.1);
              assertEquals(55L, (long) s.getTotalSum());
              return null;
            });

    pipeline.run().waitUntilFinish();
  }
}
