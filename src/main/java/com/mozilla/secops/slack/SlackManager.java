package com.mozilla.secops.slack;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.SlackApiResponse;
import com.github.seratch.jslack.api.methods.request.chat.ChatPostMessageRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersLookupByEmailRequest;
import com.github.seratch.jslack.api.methods.response.channels.UsersLookupByEmailResponse;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.users.UsersListResponse;
import com.github.seratch.jslack.api.model.Action;
import com.github.seratch.jslack.api.model.Attachment;
import com.github.seratch.jslack.api.model.Confirmation;
import com.github.seratch.jslack.api.model.User;
import com.github.seratch.jslack.common.http.SlackHttpClient;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.TlsVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SlackManager {
  private String apiToken;
  private Slack slack;
  private final Logger log;

  private ConnectionSpec getConnectionSpec() {
    return new ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
        .tlsVersions(TlsVersion.TLS_1_2)
        .allEnabledCipherSuites()
        .build();
  }

  /**
   * Construct new slack manager object
   *
   * @param apiToken Slack api token
   */
  public SlackManager(String apiToken) {
    log = LoggerFactory.getLogger(SlackManager.class);
    this.apiToken = apiToken;
    OkHttpClient okc =
        new OkHttpClient.Builder()
            .connectionSpecs(Collections.singletonList(getConnectionSpec()))
            .build();
    slack = Slack.getInstance(new SlackHttpClient(okc));
  }

  /**
   * Send message to slack channel.
   *
   * <p>If it is a private channel, the bot must be invited to that channel first.
   *
   * @param channelId Slack channel id
   * @param message Message to be sent
   * @return Message response object
   * @throws IOException IOException
   * @throws SlackApiException SlackApiException
   */
  public ChatPostMessageResponse sendMessageToChannel(String channelId, String message)
      throws IOException, SlackApiException {
    return sendChatPostMessageRequest(
        ChatPostMessageRequest.builder().token(apiToken).channel(channelId).text(message).build());
  }

  /**
   * Get slack user id from their email.
   *
   * @param email User's email
   * @return User's slack user id
   * @throws IOException IOException
   * @throws SlackApiException SlackApiException
   */
  public String lookupUserIdByEmail(String email) throws IOException, SlackApiException {
    UsersLookupByEmailResponse resp =
        slack
            .methods()
            .usersLookupByEmail(
                UsersLookupByEmailRequest.builder().token(apiToken).email(email).build());

    if (handleSlackResponse(resp)) {
      return resp.getUser().getId();
    }
    return null;
  }

  /**
   * Get map where the key is user's emails and the corresponding value is their slack id.
   *
   * @return HashMap for email to slack id
   * @throws IOException IOException
   * @throws SlackApiException SlackApiException
   */
  public HashMap<String, String> getEmailToUserIdMapping() throws IOException, SlackApiException {
    List<User> users = getUserList();
    HashMap<String, String> emailToUser = new HashMap<String, String>();
    for (User user : users) {
      emailToUser.put(user.getProfile().getEmail(), user.getId());
    }
    return emailToUser;
  }

  /**
   * Get list of all Slack users
   *
   * @return List of Slack user objects
   * @throws IOException IOException
   * @throws SlackApiException SlackApiException
   */
  public List<User> getUserList() throws IOException, SlackApiException {
    ArrayList<User> users = new ArrayList<User>();
    UsersListResponse resp =
        slack.methods().usersList(UsersListRequest.builder().token(apiToken).build());
    Boolean isOk = handleSlackResponse(resp);
    if (isOk == false) {
      log.error("failed to get user list from slack.");
      return null;
    }
    users.addAll(resp.getMembers());

    while (true) {
      if (resp.getResponseMetadata().getNextCursor() != null) {
        resp =
            slack
                .methods()
                .usersList(
                    UsersListRequest.builder()
                        .token(apiToken)
                        .cursor(resp.getResponseMetadata().getNextCursor())
                        .build());
        users.addAll(resp.getMembers());
      } else {
        break;
      }
    }

    return users;
  }

  /**
   * Send message with confirmation request to slack user.
   *
   * @param userId Slack user id to send message to
   * @param alertId Alert id to include in button callback
   * @param message Message to be sent
   * @return Message response object
   * @throws IOException IOException
   * @throws SlackApiException SlackApiException
   */
  public ChatPostMessageResponse sendConfirmationRequestToUser(
      String userId, String alertId, String message) throws IOException, SlackApiException {
    return sendChatPostMessageRequest(
        ChatPostMessageRequest.builder()
            .token(apiToken)
            .channel(userId)
            .text(message)
            .attachments(createAuthConfirmationButtons(alertId))
            .build());
  }

  private List<Attachment> createAuthConfirmationButtons(String alertId) {
    ArrayList<Action> actions = new ArrayList<Action>();
    actions.add(
        Action.builder()
            .name("alert_yes")
            .text("Yes, this was me.")
            .style("primary")
            .value("yes")
            .build());

    actions.add(
        Action.builder()
            .name("alert_no")
            .text("No, this was not me.")
            .style("danger")
            .value("no")
            .confirm(
                Confirmation.builder()
                    .title("Confirm this selection")
                    .text(
                        "It's alright if you are unsure, but please double-check before selecting 'No'.")
                    .ok_text("Yes")
                    .dismiss_text("No")
                    .build())
            .build());

    ArrayList<Attachment> attachments = new ArrayList<Attachment>();
    attachments.add(
        Attachment.builder()
            .text("Was this you?")
            .fallback("Unable to create slack buttons; please contact secops@mozilla.com")
            .callbackId(String.format("alert_confirmation_%s", alertId))
            .color("#3AA3E3")
            .actions(actions)
            .build());

    return attachments;
  }

  private ChatPostMessageResponse sendChatPostMessageRequest(ChatPostMessageRequest request)
      throws IOException, SlackApiException {
    try {
      return slack.methods().chatPostMessage(request);
    } catch (SlackApiException exc) {
      Optional<String> retryAfter = Optional.ofNullable(exc.getResponse().header("Retry-After"));
      if (retryAfter.isPresent()) {
        int wait = Integer.parseInt(retryAfter.get());
        log.info("waiting {} seconds for slack rate limit to expire.", wait);
        try {
          Thread.sleep(wait * 1000);
        } catch (InterruptedException ie) {
          log.error("waiting for rate limit to expire was interrupted.");
          log.error("stack trace: ", ie);
          Thread.currentThread().interrupt();
          throw exc;
        }
        return sendChatPostMessageRequest(request);
      }
      throw exc;
    }
  }

  /**
   * Checks if the response contains an error or warning message, and returns true if the request
   * was successful.
   *
   * @param resp Slack api response
   * @return Boolean, true if request was successful
   */
  public Boolean handleSlackResponse(SlackApiResponse resp) {
    if (resp.getError() != null && resp.getError() != "") {
      log.error("error sending slack request: {}", resp.getError());
    }
    if (resp.getWarning() != null && resp.getWarning() != "") {
      log.warn("warning from sending slack request: {}", resp.getWarning());
    }
    if (resp.isOk()) {
      return true;
    }
    return false;
  }
}
