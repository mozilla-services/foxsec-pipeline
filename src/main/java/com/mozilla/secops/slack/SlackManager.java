package com.mozilla.secops.slack;

import com.github.seratch.jslack.Slack;
import com.github.seratch.jslack.api.methods.SlackApiException;
import com.github.seratch.jslack.api.methods.request.chat.ChatPostMessageRequest;
import com.github.seratch.jslack.api.methods.request.users.UsersListRequest;
import com.github.seratch.jslack.api.methods.response.chat.ChatPostMessageResponse;
import com.github.seratch.jslack.api.methods.response.users.UsersListResponse;
import com.github.seratch.jslack.api.model.Action;
import com.github.seratch.jslack.api.model.Attachment;
import com.github.seratch.jslack.api.model.Confirmation;
import com.github.seratch.jslack.api.model.User;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class SlackManager {
  private String apiToken;
  private Slack slack;

  public SlackManager(String apiToken) {
    this.apiToken = apiToken;
    slack = Slack.getInstance();
  }

  public HashMap<String, String> getEmailToUserIdMapping() throws IOException, SlackApiException {
    List<User> users = getUserList();
    HashMap<String, String> emailToUser = new HashMap<String, String>();
    for (User user : users) {
      emailToUser.put(user.getProfile().getEmail(), user.getId());
    }
    return emailToUser;
  }

  public List<User> getUserList() throws IOException, SlackApiException {
    ArrayList<User> users = new ArrayList<User>();
    UsersListResponse resp = slack.methods().usersList(UsersListRequest.builder().build());
    users.addAll(resp.getMembers());

    while (true) {
      // TODO - Not sure if this is the right check
      if (resp.getResponseMetadata().getNextCursor() != null) {
        resp =
            slack
                .methods()
                .usersList(
                    UsersListRequest.builder()
                        .cursor(resp.getResponseMetadata().getNextCursor())
                        .build());
        users.addAll(resp.getMembers());
      } else {
        break;
      }
    }

    return users;
  }

  public Boolean sendConfirmationRequestToUser(String userId, String message)
      throws IOException, SlackApiException {
    ChatPostMessageResponse resp =
        slack
            .methods()
            .chatPostMessage(
                ChatPostMessageRequest.builder()
                    .token(apiToken)
                    .channel(userId)
                    .text(message)
                    .attachments(createConfirmationButtons())
                    .build());
    return resp.isOk();
  }

  private List<Attachment> createConfirmationButtons() {
    ArrayList<Action> actions = new ArrayList<Action>();
    actions.add(
        Action.builder()
            .name("auth_confirmation")
            .text("Yes, this was me.")
            .style("primary")
            .value("yes")
            .build());

    actions.add(
        Action.builder()
            .name("auth_confirmation")
            .text("No, this was not me.")
            .style("danger")
            .value("no")
            .confirm(
                Confirmation.builder()
                    .title("Are you sure?")
                    .text("TODO")
                    .ok_text("Yes")
                    .dismiss_text("No")
                    .build())
            .build());

    ArrayList<Attachment> attachments = new ArrayList<Attachment>();
    attachments.add(
        Attachment.builder()
            .text("Was this you?")
            .fallback("TODO")
            .callbackId("was_this_you")
            .color("#3AA3E3")
            .actions(actions)
            .build());

    return attachments;
  }
}
