package com.mozilla.secops;

import java.io.Serializable;
import java.util.UUID;
import org.apache.beam.sdk.transforms.Combine;
import org.apache.beam.sdk.transforms.Combine.CombineFn;
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

    private Long totalElements;
    private Long totalSum;
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

    /**
     * Set total elements that made up result
     *
     * @param totalElements Total element cound
     */
    public void setTotalElements(Long totalElements) {
      this.totalElements = totalElements;
    }

    /**
     * Get total elements
     *
     * @return Total element count
     */
    public Long getTotalElements() {
      return totalElements;
    }

    /** Initialize new statistics output class */
    StatsOutput() {
      sid = UUID.randomUUID();
      totalSum = 0L;
      totalElements = 0L;
      mean = 0.0;
    }
  }

  /** {@link CombineFn} for performing statistics operations on a collection of values */
  public static class StatsCombiner extends CombineFn<Long, StatsCombiner.State, StatsOutput> {
    private static final long serialVersionUID = 1L;

    private static class State implements Serializable {
      private static final long serialVersionUID = 1L;

      private final UUID sid;

      Long sum;
      Long total;

      /**
       * Return unique state ID
       *
       * @return Unique state ID
       */
      public UUID getId() {
        return sid;
      }

      @Override
      public boolean equals(Object o) {
        State s = (State) o;
        return getId().equals(s.getId());
      }

      @Override
      public int hashCode() {
        return sid.hashCode();
      }

      State() {
        sid = UUID.randomUUID();
        sum = 0L;
        total = 0L;
      }
    }

    @Override
    public State createAccumulator() {
      return new State();
    }

    @Override
    public State addInput(State state, Long input) {
      state.total++;
      state.sum += input;
      return state;
    }

    @Override
    public State mergeAccumulators(Iterable<State> states) {
      State merged = new State();
      for (State s : states) {
        merged.sum += s.sum;
        merged.total += s.total;
      }
      return merged;
    }

    @Override
    public StatsOutput extractOutput(State state) {
      StatsOutput ret = new StatsOutput();
      ret.setTotalSum(state.sum);
      ret.setTotalElements(state.total);
      if (state.total > 0L) {
        ret.setMean((double) state.sum / state.total);
      }
      return ret;
    }

    @Override
    public StatsOutput defaultValue() {
      return new StatsOutput();
    }

    StatsCombiner() {}
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
    return input.apply("stats", Combine.globally(new StatsCombiner()).withoutDefaults());
  }
}
