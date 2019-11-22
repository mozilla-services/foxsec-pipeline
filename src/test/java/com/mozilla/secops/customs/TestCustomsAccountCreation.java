package com.mozilla.secops.customs;

import static org.junit.Assert.assertEquals;

import com.mozilla.secops.customs.Customs.CustomsOptions;
import org.apache.beam.sdk.options.PipelineOptionsFactory;
import org.junit.Test;

public class TestCustomsAccountCreation {

  @Test
  public void TestTransformDoc() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreation(true);
    CustomsAccountCreation sut = new CustomsAccountCreation(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address creates %d or more accounts in one session, where a session"
                + " ends after 30 minutes of inactivity.",
            options.getAccountCreationSessionLimit());
    assertEquals(expected, doc);
  }

  @Test
  public void TestTransformDocForNonEscalated() {
    CustomsOptions options = PipelineOptionsFactory.as(Customs.CustomsOptions.class);
    options.setEscalateAccountCreation(false);
    CustomsAccountCreation sut = new CustomsAccountCreation(options);
    String doc = sut.getTransformDoc();
    String expected =
        String.format(
            "Alert if single source address creates %d or more accounts in one session, where a session"
                + " ends after 30 minutes of inactivity. (Experimental)",
            options.getAccountCreationSessionLimit());
    assertEquals(expected, doc);
  }
}
