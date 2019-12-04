package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestSourceLoginFailureDist {
  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateSourceLoginFailureDistributed(true);
    SourceLoginFailureDist sut = new SourceLoginFailureDist(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert on login failures for a particular account from %d different source addresses "
                + "in a 10 minute fixed window.",
            options.getSourceLoginFailureDistributedThreshold());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateSourceLoginFailureDistributed(false);
    SourceLoginFailureDist sut = new SourceLoginFailureDist(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert on login failures for a particular account from %d different source addresses "
                + "in a 10 minute fixed window. (Experimental)",
            options.getSourceLoginFailureDistributedThreshold());
    assertEquals(expected, doc);
  }
}
