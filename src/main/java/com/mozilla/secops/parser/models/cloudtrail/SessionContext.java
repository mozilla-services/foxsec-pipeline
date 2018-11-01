package com.mozilla.secops.parser.models.cloudtrail;

import java.util.HashMap;

/**
 * Model for sessionContext element in Cloudtrail Events
 */
public class SessionContext {
    public HashMap<String, String> attributes;
    public HashMap<String, String> sessionIssuer;
}
