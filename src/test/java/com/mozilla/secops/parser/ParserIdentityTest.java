package com.mozilla.secops.parser;

import org.junit.Test;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.maxmind.geoip2.model.CityResponse;

import org.joda.time.DateTime;

import com.mozilla.secops.identity.IdentityManager;

public class ParserIdentityTest {
    public ParserIdentityTest() {
    }

    @Test
    public void testOpenSSHStackdriverWithIdentity() throws Exception {
        String buf = "{\"insertId\":\"f8p4mz1a3ldcos1xz\",\"labels\":{\"compute.googleapis.com/resource_" +
            "name\":\"emit-bastion\"},\"logName\":\"projects/sandbox-00/logs/syslog\",\"receiveTimestamp\"" +
            ":\"2018-09-20T18:43:38.318580313Z\",\"resource\":{\"labels\":{\"instance_id\":\"9999999999999" +
            "999999\",\"project_id\":\"sandbox-00\",\"zone\":\"us-east1-b\"},\"type\":\"gce_instance\"},\"" +
            "textPayload\":\"Sep 18 22:15:38 emit-bastion sshd[2644]: Accepted publickey for riker from 12" +
            "7.0.0.1 port 58530 ssh2: RSA SHA256:dd/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"timestamp" +
            "\":\"2018-09-18T22:15:38Z\"}";
        IdentityManager mgr = IdentityManager.loadFromResource("/testdata/identitymanager.json");
        Parser p = new Parser();
        p.setIdentityManager(mgr);
        assertNotNull(p);
        Event e = p.parse(buf);
        assertNotNull(e);
        assertEquals(Payload.PayloadType.OPENSSH, e.getPayloadType());
        OpenSSH o = e.getPayload();
        assertNotNull(o);
        assertEquals("riker", o.getUser());
        assertEquals("publickey", o.getAuthMethod());
        assertEquals("127.0.0.1", o.getSourceAddress());
        assertNull(o.getSourceAddressCity());
        assertNull(o.getSourceAddressCountry());
        Normalized n = e.getNormalized();
        assertNotNull(n);
        assertEquals(Normalized.Type.AUTH, n.getType());
        assertEquals("riker", n.getSubjectUser());
        assertEquals("wriker@mozilla.com", n.getSubjectUserIdentity());
        assertEquals("127.0.0.1", n.getSourceAddress());
    }
}
