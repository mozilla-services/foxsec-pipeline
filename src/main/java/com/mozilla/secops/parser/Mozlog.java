package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.datatype.joda.JodaModule;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

import org.joda.time.DateTime;

import java.io.Serializable;
import java.io.IOException;
import java.util.Map;

/**
 * Mozlog event encapsulation
 *
 * <p>See also https://wiki.mozilla.org/Firefox/Services/Logging#MozLog_application_logging_standard
 */
@JsonIgnoreProperties({"EnvVersion"})
public class Mozlog implements Serializable {
    private static final long serialVersionUID = 1L;

    private Integer severity;
    private Integer pid;
    private String logger;
    private String type;
    private Long timestamp;
    private String hostname;
    private DateTime time;
    private Map<String, Object> fields;

    /**
     * Get time value
     *
     * @return Time value
     */
    @JsonProperty("time")
    public DateTime getTime() {
        return time;
    }

    /**
     * Get hostname
     *
     * @return hostname
     */
    @JsonProperty("hostname")
    public String getHostname() {
        return hostname;
    }

    /**
     * Get logger value
     *
     * @return logger
     */
    @JsonProperty("logger")
    public String getLogger() {
        return logger;
    }

    /**
     * Get timestamp
     *
     * @return timestamp
     */
    @JsonProperty("timestamp")
    public Long getTimestamp() {
        return timestamp;
    }

    /**
     * Get type
     *
     * @return type
     */
    @JsonProperty("type")
    public String getType() {
        return type;
    }

    /**
     * Get severity integer
     *
     * @return severity
     */
    @JsonProperty("severity")
    public Integer getSeverity() {
        return severity;
    }

    /**
     * Get pid
     *
     * @return pid
     */
    @JsonProperty("pid")
    public Integer getPid() {
        return pid;
    }

    /**
     * Get fields
     *
     * @return fields
     */
    @JsonProperty("fields")
    public Map<String, Object> getFields() {
        return fields;
    }

    /**
     * Get fields as JSON string
     *
     * <p>Returns the Mozlog fields as a JSON string value
     *
     * @return Fields as JSON
     */
    public String getFieldsAsJson() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
            false);
        try {
            return mapper.writeValueAsString(fields);
        } catch (JsonProcessingException exc) {
            return null;
        }
    }

    /**
     * Create a new {@link Mozlog} object using a JSON string as input
     *
     * @param input Mozlog JSON event
     * @return Mozlog event or null if deserialization failed
     */
    public static Mozlog fromJSON(String input) {
        Mozlog ret;

        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JodaModule());
        mapper.configure(com.fasterxml.jackson.databind.SerializationFeature.WRITE_DATES_AS_TIMESTAMPS,
            false);
        // Not all Mozlog implementations use lower case field names
        mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, true);

        try {
            ret = mapper.readValue(input, Mozlog.class);
        } catch (IOException exc) {
            return null;
        }

        return ret;
    }

    public Mozlog() {
    }
}
