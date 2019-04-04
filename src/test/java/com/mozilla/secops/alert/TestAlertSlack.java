package com.mozilla.secops.alert;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.github.seratch.jslack.api.methods.SlackApiResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.mozilla.secops.slack.SlackManager;
import com.mozilla.secops.state.MemcachedStateInterface;
import com.mozilla.secops.state.State;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class TestAlertSlack {

  private AlertConfiguration getTestAlertCfg() {
    AlertConfiguration cfg = new AlertConfiguration();
    cfg.setMemcachedHost("127.0.0.1");
    cfg.setMemcachedPort(11211);
    cfg.setSlackToken("test");
    return cfg;
  }

  private Alert getTestAlert() {
    Alert a = new Alert();
    return a;
  }

  private SlackManager getMockSlackManager() throws Exception {
    SlackManager slackManagerMock = mock(SlackManager.class);
    when(slackManagerMock.sendConfirmationRequestToUser(anyString(), anyString(), anyString()))
        .thenReturn(new ChatPostMessageResponse());
    when(slackManagerMock.handleSlackResponse(any(SlackApiResponse.class))).thenReturn(true);
    return slackManagerMock;
  }

  @Test
  public void basicTest() throws Exception {
    AlertSlack s = new AlertSlack(getTestAlertCfg());
    assertNotNull(s);
  }

  @Test
  public void confirmationAlertBasicTest() throws Exception {
    AlertSlack s = new AlertSlack(getTestAlertCfg());

    Boolean resultOne = s.confirmationAlert(null, "test");
    assertFalse(resultOne);
    Boolean resultTwo = s.confirmationAlert(getTestAlert(), null);
    assertFalse(resultTwo);
  }

  @Test
  public void confirmationAlertStateTest() throws Exception {
    AlertConfiguration cfg = getTestAlertCfg();
    AlertSlack s = new AlertSlack(cfg, getMockSlackManager());

    Alert ta = getTestAlert();
    Boolean result = s.confirmationAlert(ta, "test");
    assertTrue(result);

    State state =
        new State(new MemcachedStateInterface(cfg.getMemcachedHost(), cfg.getMemcachedPort()));
    state.initialize();
    Alert a = state.get(ta.getAlertId().toString(), Alert.class);
    assertNotNull(a);
    assertEquals(a.getTimestamp(), ta.getTimestamp());
    assertEquals(a.getMetadataValue("status"), "NEW");
  }
}
