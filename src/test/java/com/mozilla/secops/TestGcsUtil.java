package com.mozilla.secops;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.cloud.storage.BlobId;
import org.junit.Test;

public class TestGcsUtil {
  public TestGcsUtil() {}

  @Test
  public void GcsIsGcsUrlTest() throws Exception {
    assertTrue(GcsUtil.isGcsUrl("gs://bucket/path/object"));
    assertFalse(GcsUtil.isGcsUrl("/path/object"));
    assertFalse(GcsUtil.isGcsUrl("gs://"));
    assertFalse(GcsUtil.isGcsUrl("gs://test"));
    assertFalse(GcsUtil.isGcsUrl("gs://test/"));

    BlobId bid = GcsUtil.blobIdFromUrl("gs://bucket/path");
    assertEquals("bucket", bid.getBucket());
    assertEquals("path", bid.getName());

    bid = GcsUtil.blobIdFromUrl("gs://bucket/path/test");
    assertEquals("bucket", bid.getBucket());
    assertEquals("path/test", bid.getName());

    bid = GcsUtil.blobIdFromUrl("/test/path");
    assertNull(bid);
  }
}
