package com.mozilla.secops;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class TestMiscUtil {
  public TestMiscUtil() {}

  @Test
  public void testNormalizeEmailPlus() throws Exception {
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlus("test@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlus("test+x@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlus("test+x+x@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlus("test+@mozilla.com"));
    assertEquals("+@mozilla.com", MiscUtil.normalizeEmailPlus("+@mozilla.com"));

    // Malformed input should just return the original string
    assertEquals("test", MiscUtil.normalizeEmailPlus("test"));
    assertEquals("test@", MiscUtil.normalizeEmailPlus("test@"));
    assertEquals("test+x@", MiscUtil.normalizeEmailPlus("test+x@"));
    assertEquals("+", MiscUtil.normalizeEmailPlus("+"));
    assertEquals("", MiscUtil.normalizeEmailPlus(""));
  }

  @Test
  public void testNormalizeEmailPlusDotStrip() throws Exception {
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("test@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("test.@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("test.+x@mozilla.com"));
    assertEquals("test@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("test.+@mozilla.com"));
    assertEquals(
        "test@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("test+test.test@mozilla.com"));
    assertEquals(".@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip(".@mozilla.com"));
    assertEquals("..@mozilla.com", MiscUtil.normalizeEmailPlusDotStrip("..@mozilla.com"));
  }
}
