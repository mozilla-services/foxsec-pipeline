package com.mozilla.secops.parser;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mozilla.secops.parser.models.aws.guardduty.GuardDutyFinding;

import java.io.Serializable;

/** Payload parser for AWS GuardDuty Finding data */
public class GuardDuty extends PayloadBase implements Serializable {
    private static final long serialVersionUID = 1L;

    private ObjectMapper mapper;
    private GuardDutyFinding gdf;

    @Override
    public Boolean matcher(String input, ParserState state) {
        return (input.contains("aws.guardduty"));
    }

    @Override
    public Payload.PayloadType getType() {
        return Payload.PayloadType.GUARDDUTY;
    }

    /** Construct matcher object. */
    public GuardDuty() {}

    /**
     * Construct parser object.
     *
     * @param input Input string
     */
    public GuardDuty(String input, Event e, ParserState s) {
        mapper = new ObjectMapper();
        try {
            gdf = mapper.readValue(input, GuardDutyFinding.class);
        } catch (Exception exc) {
            System.out.println(exc.getMessage());
            return;
        }
    }
}
