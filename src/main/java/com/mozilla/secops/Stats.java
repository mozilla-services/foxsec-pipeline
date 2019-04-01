package com.mozilla.secops;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.UUID;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.CombineWithContext.CombineFnWithContext;
import org.apache.beam.sdk.transforms.CombineWithContext.Context;
import org.apache.beam.sdk.transforms.Mean;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.View;
import org.apache.beam.sdk.values.PCollection;
import org.apache.beam.sdk.values.PCollectionView;

/**
 * Generic statistics class
 *
 * <p>Currently only operates on collections of {@link Long} values
 */
public class Stats extends PTransform<PCollection<Long>, PCollection<Stats.StatsOutput>> {
  private static final long serialVersionUID = 1L;

  /** Output of statistics transform */
  public static class StatsOutput implements Serializable {
    private static final long serialVersionUID = 1L;

    private final UUID sid;

    private Long totalSum;
    private Double popVar;
    private Double mean;

    @Override
    public boolean equals(Object o) {
      StatsOutput s = (StatsOutput) o;
      return getOutputId().equals(s.getOutputId());
    }

    @Override
    public int hashCode() {
      return sid.hashCode();
    }

    /**
     * Return unique output ID
     *
     * @return Unique output ID
     */
    public UUID getOutputId() {
      return sid;
    }

    /**
     * Get mean value of set
     *
     * @return Mean value
     */
    public Double getMean() {
      return mean;
    }

    /**
     * Set mean value in result
     *
     * @param mean Mean value
     */
    public void setMean(Double mean) {
      this.mean = mean;
    }

    /**
     * Get set population variance
     *
     * @return Population variance
     */
    public Double getPopulationVariance() {
      return popVar;
    }

    /**
     * Set population variance in result
     *
     * @param popVar Population variance
     */
    public void setPopulationVariance(Double popVar) {
      this.popVar = popVar;
    }

    /**
     * Set total sum in result
     *
     * @param totalSum Total sum
     */
    public void setTotalSum(Long totalSum) {
      this.totalSum = totalSum;
    }

    /**
     * Get total sum
     *
     * @return Total sum
     */
    public Long getTotalSum() {
      return totalSum;
    }

    /** Initialize new statistics output class */
    StatsOutput() {
      sid = UUID.randomUUID();
      totalSum = 0L;
      popVar = 0.0;
      mean = 0.0;
    }
  }

  /** {@link CombineFnWithContext} for performing statistics operations on a collection of values */
  public static class StatsCombiner
      extends CombineFnWithContext<Long, StatsCombiner.State, StatsOutput> {
    private static final long serialVersionUID = 1L;

    private PCollectionView<Double> meanValue;

    private static class State implements Serializable {
      private static final long serialVersionUID = 1L;

      Long sum;
      ArrayList<Double> varianceSq;

      State() {
        sum = 0L;
        varianceSq = new ArrayList<Double>();
      }
    }

    @Override
    public State createAccumulator(Context c) {
      return new State();
    }

    @Override
    public State addInput(State state, Long input, Context c) {
      state.sum += input;
      state.varianceSq.add(Math.pow(input - c.sideInput(meanValue), 2));
      return state;
    }

    @Override
    public State mergeAccumulators(Iterable<State> states, Context c) {
      State merged = new State();
      for (State s : states) {
        merged.sum += s.sum;
        merged.varianceSq.addAll(s.varianceSq);
      }
      return merged;
    }

    @Override
    public StatsOutput extractOutput(State state, Context c) {
      Double mean = c.sideInput(meanValue);
      StatsOutput ret = new StatsOutput();
      ret.setTotalSum(state.sum);
      Double x = 0.0;
      for (Double y : state.varianceSq) {
        x += y;
      }
      ret.setPopulationVariance(x / state.varianceSq.size());
      ret.setMean(mean);
      return ret;
    }

    @Override
    public StatsOutput defaultValue() {
      return new StatsOutput();
    }

    StatsCombiner(PCollectionView<Double> meanValue) {
      this.meanValue = meanValue;
    }
  }

  Stats() {}

  /**
   * Execute the transform returning a {@link PCollectionView} suitable for use as a side input
   *
   * @param input Input data set
   * @return {@link PCollectionView} representing results of analysis
   */
  public static PCollectionView<StatsOutput> getView(PCollection<Long> input) {
    return input
        .apply("stats transform", new Stats())
        .apply("stats view", View.<StatsOutput>asSingleton().withDefaultValue(new StatsOutput()));
  }

  @Override
  public PCollection<StatsOutput> expand(PCollection<Long> input) {
    PCollectionView<Double> meanValue =
        input.apply("stats mean calculation", Mean.<Long>globally().asSingletonView());
    return input.apply(
        "stats",
        Combine.globally(new StatsCombiner(meanValue)).withoutDefaults().withSideInputs(meanValue));
  }
}
