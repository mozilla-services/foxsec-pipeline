package com.mozilla.secops.httprequest;

public class HTTPRequestToggles {
  // Mode toggles
  private Boolean enableThresholdAnalysis = false;
  private Boolean enableErrorRateAnalysis = false;
  private Boolean enableEndpointAbuseAnalysis = false;
  private Boolean enableHardLimitAnalysis = false;
  private Boolean enableUserAgentBlacklistAnalysis = false;
  private Boolean enableNatDetection = false;

  // Hard limit settings
  private Long hardLimitRequestCount = 100L;

  // Threshold analysis settings
  private Double analysisThresholdModifier = 75.0;
  private Double requiredMinimumAverage = 5.0;
  private Long requiredMinimumClients = 5L;
  private Double clampThresholdMaximum;

  // Error rate settings
  private Long maxClientErrorRate = 30L;

  // User agent blacklist settings
  private String userAgentBlacklistPath;

  // Endpoint abuse settings
  private String[] endpointAbusePath;
  private Boolean endpointAbuseExtendedVariance = false;
  private String[] endpointAbuseCustomVarianceSubstrings;
  private Integer endpointAbuseSuppressRecovery;
  private Long sessionGapDurationMinutes = 45L;

  // Filtering settings
  private String[] filterRequestPath;
  private String[] includeUrlHostRegex;
  private String cidrExclusionList;
  private Boolean ignoreCloudProviderRequests = true;
  private Boolean ignoreInternalRequests = true;

  public void setEnableThresholdAnalysis(Boolean enableThresholdAnalysis) {
    this.enableThresholdAnalysis = enableThresholdAnalysis;
  }

  public Boolean getEnableThresholdAnalysis() {
    return enableThresholdAnalysis;
  }

  public void setAnalysisThresholdModifier(Double value) {
    analysisThresholdModifier = value;
  }

  public Double getAnalysisThresholdModifier() {
    return analysisThresholdModifier;
  }

  public void setRequiredMinimumAverage(Double value) {
    requiredMinimumAverage = value;
  }

  public Double getRequiredMinimumAverage() {
    return requiredMinimumAverage;
  }

  public void setRequiredMinimumClients(Long value) {
    requiredMinimumClients = value;
  }

  public Long getRequiredMinimumClients() {
    return requiredMinimumClients;
  }

  public void setClampThresholdMaximum(Double value) {
    clampThresholdMaximum = value;
  }

  public Double getClampThresholdMaximum() {
    return clampThresholdMaximum;
  }

  public void setEnableErrorRateAnalysis(Boolean enableErrorRateAnalysis) {
    this.enableErrorRateAnalysis = enableErrorRateAnalysis;
  }

  public Boolean getEnableErrorRateAnalysis() {
    return enableErrorRateAnalysis;
  }

  public void setMaxClientErrorRate(Long value) {
    maxClientErrorRate = value;
  }

  public Long getMaxClientErrorRate() {
    return maxClientErrorRate;
  }

  public void setEnableEndpointAbuseAnalysis(Boolean enableEndpointAbuseAnalysis) {
    this.enableEndpointAbuseAnalysis = enableEndpointAbuseAnalysis;
  }

  public Boolean getEnableEndpointAbuseAnalysis() {
    return enableEndpointAbuseAnalysis;
  }

  public void setEnableHardLimitAnalysis(Boolean enableHardLimitAnalysis) {
    this.enableHardLimitAnalysis = enableHardLimitAnalysis;
  }

  public void setEndpointAbusePath(String[] value) {
    endpointAbusePath = value;
  }

  public String[] getEndpointAbusePath() {
    return endpointAbusePath;
  }

  public void setEndpointAbuseExtendedVariance(Boolean value) {
    endpointAbuseExtendedVariance = value;
  }

  public Boolean getEndpointAbuseExtendedVariance() {
    return endpointAbuseExtendedVariance;
  }

  public void setEndpointAbuseCustomVarianceSubstrings(String[] value) {
    endpointAbuseCustomVarianceSubstrings = value;
  }

  public String[] getEndpointAbuseCustomVarianceSubstrings() {
    return endpointAbuseCustomVarianceSubstrings;
  }

  public void setEndpointAbuseSuppressRecovery(Integer value) {
    endpointAbuseSuppressRecovery = value;
  }

  public Integer getEndpointAbuseSuppressRecovery() {
    return endpointAbuseSuppressRecovery;
  }

  public void setSessionGapDurationMinutes(Long value) {
    sessionGapDurationMinutes = value;
  }

  public Long getSessionGapDurationMinutes() {
    return sessionGapDurationMinutes;
  }

  public Boolean getEnableHardLimitAnalysis() {
    return enableHardLimitAnalysis;
  }

  public void setHardLimitRequestCount(Long value) {
    hardLimitRequestCount = value;
  }

  public Long getHardLimitRequestCount() {
    return hardLimitRequestCount;
  }

  public void setEnableUserAgentBlacklistAnalysis(Boolean enableUserAgentBlacklistAnalysis) {
    this.enableUserAgentBlacklistAnalysis = enableUserAgentBlacklistAnalysis;
  }

  public Boolean getEnableUserAgentBlacklistAnalysis() {
    return enableUserAgentBlacklistAnalysis;
  }

  public void setUserAgentBlacklistPath(String value) {
    userAgentBlacklistPath = value;
  }

  public String getUserAgentBlacklistPath() {
    return userAgentBlacklistPath;
  }

  public void setFilterRequestPath(String[] value) {
    filterRequestPath = value;
  }

  public String[] getFilterRequestPath() {
    return filterRequestPath;
  }

  public void setIncludeUrlHostRegex(String[] value) {
    includeUrlHostRegex = value;
  }

  public String[] getIncludeUrlHostRegex() {
    return includeUrlHostRegex;
  }

  public void setCidrExclusionList(String value) {
    cidrExclusionList = value;
  }

  public String getCidrExclusionList() {
    return cidrExclusionList;
  }

  public void setIgnoreCloudProviderRequests(Boolean value) {
    ignoreCloudProviderRequests = value;
  }

  public Boolean getIgnoreCloudProviderRequests() {
    return ignoreCloudProviderRequests;
  }

  public void setIgnoreInternalRequests(Boolean value) {
    ignoreInternalRequests = value;
  }

  public Boolean getIgnoreInternalRequests() {
    return ignoreInternalRequests;
  }

  public HTTPRequestToggles() {}
}
