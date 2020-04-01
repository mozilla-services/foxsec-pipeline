package com.mozilla.secops.gatekeeper;

import com.amazonaws.services.guardduty.model.Action;
import com.amazonaws.services.guardduty.model.Finding;
import com.amazonaws.services.guardduty.model.Tag;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * {@link GuardDutyFindingMatcher} is used for matching against Guardduty findings, used by {@link
 * GatekeeperPipeline} to bucket findings into different categories
 */
public class GuardDutyFindingMatcher implements Serializable {
  private static final long serialVersionUID = 1L;

  private String findingType;
  private Pattern findingTypeMatcher;
  private Map<String, String> awsTags;
  private Map<String, Pattern> awsTagsPatterned;
  private String accountId;
  private String domainName;

  /**
   * Set the finding type to match against
   *
   * @param findingType finding type string (regex supported)
   */
  @JsonProperty("finding_type")
  public void setFindingType(String findingType) {
    this.findingType = findingType;
    if (findingType != null) {
      findingTypeMatcher = Pattern.compile(findingType);
    }
  }

  /**
   * Set the aws tags to match against
   *
   * @param awsTags map of tags to match against, values support regex.
   */
  @JsonProperty("aws_tags")
  public void setAwsTags(Map<String, String> awsTags) {
    this.awsTags = awsTags;
    awsTagsPatterned = new HashMap<String, Pattern>();
    for (Map.Entry<String, String> tag : awsTags.entrySet()) {
      awsTagsPatterned.put(tag.getKey(), Pattern.compile(tag.getValue()));
    }
  }

  /**
   * Set the account id to match against
   *
   * @param accountId aws account id string
   */
  @JsonProperty("account_id")
  public void setAccountId(String accountId) {
    this.accountId = accountId;
  }

  /**
   * Set the domain name to match against within the finding
   *
   * @param domainName domain string
   */
  @JsonProperty("domain_name")
  public void setDomainName(String domainName) {
    this.domainName = domainName;
  }

  /**
   * Checks if a Finding matches this matcher. This is done by comparing the finding type, account
   * id, tags, and domain name (from Finding). If one (or more) of these are unset, it is ignored.
   *
   * @param f Guardduty {@link Finding}
   * @return boolean
   */
  public boolean matches(Finding f) {
    boolean ftMatches = false;
    boolean idMatches = false;
    boolean tagMatches = false;
    boolean domainMatches = false;

    // Check finding type
    if (findingType != null) {
      if (f.getType() == null) {
        return false;
      }
      if (findingTypeMatcher.matcher(f.getType()).matches()) {
        ftMatches = true;
      }
    } else {
      ftMatches = true;
    }

    // Check account id
    if (accountId != null) {
      if (f.getAccountId() == null) {
        return false;
      }
      if (f.getAccountId().equals(accountId)) {
        idMatches = true;
      }
    } else {
      idMatches = true;
    }

    // Check resource tags
    if (awsTags != null) {
      if (f.getResource() == null
          || f.getResource().getInstanceDetails() == null
          || f.getResource().getInstanceDetails().getTags() == null) {
        return false;
      }

      List<Tag> tags = f.getResource().getInstanceDetails().getTags();
      int trueCnt = 0;
      for (Tag tag : tags) {
        for (Map.Entry<String, Pattern> matcherTag : awsTagsPatterned.entrySet()) {
          if (tag.getKey().equals(matcherTag.getKey())
              && matcherTag.getValue().matcher(tag.getValue()).matches()) {
            trueCnt++;
          }
        }
      }
      if (trueCnt >= awsTags.size()) {
        tagMatches = true;
      }
    } else {
      tagMatches = true;
    }

    // Check domain matches
    if (domainName != null) {
      if (f.getService() == null || f.getService().getAction() == null) {
        return false;
      }
      Action ac = f.getService().getAction();
      if (ac.getActionType().equals("DNS_REQUEST")) {
        if (ac.getDnsRequestAction().getDomain().equals(domainName)) {
          domainMatches = true;
        }
      }
    } else {
      domainMatches = true;
    }

    return ftMatches && idMatches && tagMatches && domainMatches;
  }
}
