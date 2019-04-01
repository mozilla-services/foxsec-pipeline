package com.mozilla.secops;

import com.google.cloud.storage.Blob;
import com.google.cloud.storage.BlobId;
import com.google.cloud.storage.BlobInfo;
import com.google.cloud.storage.Storage;
import com.google.cloud.storage.StorageException;
import com.google.cloud.storage.StorageOptions;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Utilities for requesting content from Google Cloud Storage */
public final class GcsUtil {
  private static final String gcsUrlRe = "^gs://([^/]+)/(\\S+)";

  /**
   * Get signed url from GCS Url (gs://...)
   *
   * @param input Input string
   * @return URL signed url
   */
  public static java.net.URL signedUrlFromGcsUrl(String input) {
    BlobId bid = blobIdFromUrl(input);
    if (bid == null) {
      return null;
    }
    Storage storage = StorageOptions.getDefaultInstance().getService();
    // check if blob exists
    Blob blob = storage.get(bid);
    if (blob == null || !blob.exists()) {
      return null;
    }
    try {
      return storage.signUrl(BlobInfo.newBuilder(bid).build(), 10, TimeUnit.MINUTES);
    } catch (IllegalStateException exc) {
      return null;
    } catch (com.google.auth.ServiceAccountSigner.SigningException exc) {
      return null;
    }
  }

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
   * Fetch byte array from specified storage URL
   *
   * @param inputUrl Input URL, e.g., gs://bucket/path
   * @return Byte array or null of not found or an error occurs
   */
  public static byte[] fetchContent(String inputUrl) {
    Storage storage = StorageOptions.getDefaultInstance().getService();
    BlobId bid = blobIdFromUrl(inputUrl);
    if (bid == null) {
      return null;
    }
    try {
      return storage.readAllBytes(bid);
    } catch (StorageException exc) {
      return null;
    }
  }

  /**
   * Fetch string content from specified storage URL
   *
   * @param inputUrl Input URL, e.g., gs://bucket/path
   * @return Trimmed string or null if not found or an error occurs
   */
  public static String fetchStringContent(String inputUrl) {
    byte[] buf = fetchContent(inputUrl);
    if (buf == null) {
      return null;
    }
    return new String(buf).trim();
  }

  /**
   * Fetch InputStream from specified storage URL
   *
   * @param inputUrl Input URL, e.g., gs://bucket/path
   * @return InputStream or null if not found or an error occurs
   */
  public static InputStream fetchInputStreamContent(String inputUrl) {
    byte[] buf = fetchContent(inputUrl);
    if (buf == null) {
      return null;
    }
    return new ByteArrayInputStream(buf);
  }

  GcsUtil() {}
}
