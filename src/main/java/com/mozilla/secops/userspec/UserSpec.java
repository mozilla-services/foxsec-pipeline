package com.mozilla.secops.userspec;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.type.TypeFactory;

import java.io.IOException;
import java.io.InputStream;

import java.util.Map;
import java.util.List;

class UserSpecRoot {
    private Map<String, UserSpecRootEntity> identities;

    public Map<String, UserSpecRootEntity> getIdentities() {
        return identities;
    }
}

class UserSpecRootEntity {
    private List<String> aliases;

    public List<String> getAliases() {
        return aliases;
    }
}

public class UserSpec {
    private UserSpecRoot specroot;

    public UserSpec(InputStream is) throws java.io.IOException {
        ObjectMapper mapper = new ObjectMapper();
        specroot = mapper.readValue(is, UserSpecRoot.class);
    }
}
