package com.mozilla.secops.alert;

public class AlertTemplate {
  private String type;
  private String name;

  public String getPath() {
    return type + "/" + name;
  }

  public String getType() {
    return type;
  }

  public AlertTemplate(String type, String name) {
    this.type = type;
    this.name = name;
  }
}
