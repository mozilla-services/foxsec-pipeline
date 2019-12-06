package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsAccountCreationDist {

  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreationDistributed(true);
    CustomsAccountCreationDist sut = new CustomsAccountCreationDist(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if at least %d accounts are created from different source addresses in "
                + "a 10 minute fixed window and the similarity index of the accounts is all below %.2f.",
            options.getAccountCreationDistributedThreshold(),
            options.getAccountCreationDistributedDistanceRatio());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreationDistributed(false);
    CustomsAccountCreationDist sut = new CustomsAccountCreationDist(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if at least %d accounts are created from different source addresses in "
                + "a 10 minute fixed window and the similarity index of the accounts is all "
                + "below %.2f. (Experimental)",
            options.getAccountCreationDistributedThreshold(),
            options.getAccountCreationDistributedDistanceRatio());
    assertEquals(expected, doc);
  }
}
