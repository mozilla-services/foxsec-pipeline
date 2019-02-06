package com.mozilla.secops;

import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageOptions;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Utilities for requesting content from Google Cloud Storage */
public final class GcsUtil {
  private static final String gcsUrlRe = "^gs://([^/]+)/(\\S+)";

  /**
   * Return true if the input string looks like a Google Cloud Storage URL
   *
   * @param input Input string
   * @return Boolean
   */
  public static Boolean isGcsUrl(String input) {
    return Pattern.compile(gcsUrlRe).matcher(input).matches();
  }

  /**
   * Return a storage {@link BlobId} given a storage input URL
   *
   * @param input Input URL, e.g., gs://bucket/path
   * @return BlobId or null on invalid input
   */
  public static BlobId blobIdFromUrl(String input) {
    Matcher mat = Pattern.compile(gcsUrlRe).matcher(input);
    if (!mat.matches()) {
      return null;
    }
    return BlobId.of(mat.group(1), mat.group(2));
  }

  /**
   * Fetch content from specified storage URL
   *
   * @param inputUrl Input URL, e.g., gs://bucket/path
   * @return Trimmed string or null if not found or an error occurs
   */
  public static String fetchStringContent(String inputUrl) {
    Storage storage = StorageOptions.getDefaultInstance().getService();
    BlobId bid = blobIdFromUrl(inputUrl);
    if (bid == null) {
      return null;
    }
    byte[] content = storage.readAllBytes(bid);
    return new String(content).trim();
  }

  GcsUtil() {}
}
