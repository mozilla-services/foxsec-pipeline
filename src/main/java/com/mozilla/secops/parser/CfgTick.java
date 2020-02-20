package com.mozilla.secops.parser;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/** Payload parser for configuration ticks */
public class CfgTick extends PayloadBase implements Serializable {
  private static final long serialVersionUID = 1L;

  private Map<String, String> configMap;

  @Override
  public Boolean matcher(String input, ParserState state) {
    Map<String, Object> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return false;
    }
    if (fields.get("configuration_tick") != null) {
      return true;
    }
    return false;
  }

  /**
   * Get configuration map
   *
   * @return Map of key/value string pairs
   */
  public Map<String, String> getConfigurationMap() {
    return configMap;
  }

  @Override
  @JsonProperty("type")
  public Payload.PayloadType getType() {
    return Payload.PayloadType.CFGTICK;
  }

  /** Construct matcher object. */
  public CfgTick() {}

  private static String convertArray(Object o) {
    ArrayList<String> buf = new ArrayList<>();
    if (o instanceof ArrayList<?>) {
      ArrayList<?> a = (ArrayList<?>) o;
      for (int i = 0; i < a.size(); i++) {
        Object v = a.get(i);
        // XXX Just support conversion of string and integer here right now
        if (v instanceof String) {
          buf.add((String) v);
        } else if (v instanceof Integer) {
          buf.add(((Integer) v).toString());
        } else {
          return null;
        }
      }
    } else {
      return null;
    }
    return String.join(", ", buf);
  }

  /**
   * Convert a map of type String, Object into a map of type String, String
   *
   * <p>Any arrays that are present in the input are flattened into a root level value with each
   * element delimited by a comma.
   *
   * <p>This is a local implementation that has support for basic types that are expected to be seen
   * in pipeline options and is likely not suitable for more general use.
   *
   * @param in Input map
   * @return Converted map
   * @throws IOException IOException
   */
  public static HashMap<String, String> flattenObjectMapToStringMap(Map<String, Object> in)
      throws IOException {
    HashMap<String, String> ret = new HashMap<>();

    for (Map.Entry<String, Object> entry : in.entrySet()) {
      Object o = entry.getValue();
      if (o instanceof Boolean) {
        ret.put(entry.getKey(), ((Boolean) o).toString());
      } else if (o instanceof Integer) {
        ret.put(entry.getKey(), ((Integer) o).toString());
      } else if (o instanceof String) {
        ret.put(entry.getKey(), (String) o);
      } else if (o instanceof Double) {
        ret.put(entry.getKey(), ((Double) o).toString());
      } else if (o instanceof ArrayList) {
        String abuf = convertArray(o);
        if (abuf == null) {
          throw new IOException("map had array which could not be converted");
        }
        ret.put(entry.getKey(), abuf);
      } else {
        throw new IOException(
            String.format(
                "map had value type that could not be converted, %s", o.getClass().toString()));
      }
    }

    return ret;
  }

  /**
   * Construct parser object.
   *
   * @param input Input string.
   * @param e Parent {@link Event}.
   * @param state State
   */
  public CfgTick(String input, Event e, ParserState state) {
    Map<String, Object> fields = Parser.convertJsonToMap(input);
    if (fields == null) {
      return;
    }
    try {
      configMap = flattenObjectMapToStringMap(fields);
    } catch (IOException exc) {
      // pass
    }
  }
}
