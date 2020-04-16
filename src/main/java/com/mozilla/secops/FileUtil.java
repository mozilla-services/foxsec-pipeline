package com.mozilla.secops;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Scanner;

/** Various utilities for file IO */
public class FileUtil {
  /**
   * Read file from specified path, returning an {@link ArrayList} containing an item for each line
   *
   * <p>Lines beginning with a # character are treated as comments and not returned in the result
   * set.
   *
   * @param path Resource path or GCS URL to read file from
   * @throws IOException IOException
   * @return {@link ArrayList} containing line items
   */
  public static ArrayList<String> fileReadLines(String path) throws IOException {
    InputStream in = getStreamFromPath(path);
    ArrayList<String> ret = new ArrayList<>();
    Scanner s = new Scanner(in).useDelimiter("\\n");
    while (s.hasNext()) {
      String n = s.next();
      if (n.startsWith("#")) {
        continue;
      }
      ret.add(n);
    }
    return ret;
  }

  /**
   * Read file from specified path, returning an {@link InputStream} for processing
   *
   * <p>This supports both resource path and GCS URL to read from
   *
   * @param path Resource path or GCS URL to read file from
   * @throws IOException IOException
   * @return {@link InputStream} for reading resource
   */
  public static InputStream getStreamFromPath(String path) throws IOException {
    InputStream in;
    if (path == null || path.isEmpty()) {
      throw new IOException("attempt to load file with null or empty path");
    }
    if (GcsUtil.isGcsUrl(path)) {
      in = GcsUtil.fetchInputStreamContent(path);
    } else {
      in = FileUtil.class.getResourceAsStream(path);
    }
    if (in == null) {
      throw new IOException(String.format("failed to read file from path %s", path));
    }
    return in;
  }
}
