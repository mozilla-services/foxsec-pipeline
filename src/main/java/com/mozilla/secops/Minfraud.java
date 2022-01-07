package com.mozilla.secops;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.InjectableValues;
import com.fasterxml.jackson.databind.InjectableValues.Std;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.util.StdDateFormat;
import com.maxmind.minfraud.WebServiceClient;
import com.maxmind.minfraud.exception.AuthenticationException;
import com.maxmind.minfraud.exception.HttpException;
import com.maxmind.minfraud.exception.InsufficientFundsException;
import com.maxmind.minfraud.exception.InvalidRequestException;
import com.maxmind.minfraud.exception.MinFraudException;
import com.maxmind.minfraud.exception.PermissionRequiredException;
import com.maxmind.minfraud.request.Device;
import com.maxmind.minfraud.request.Email;
import com.maxmind.minfraud.request.Transaction;
import com.maxmind.minfraud.response.InsightsResponse;
import com.mozilla.secops.crypto.RuntimeSecrets;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Query Maxmind minFraud API */
public class Minfraud implements Serializable {
  private static final long serialVersionUID = 1L;
  private final Logger log;
  private WebServiceClient mfClient;
  private static Boolean cacheOnly = false;

  private static HashMap<String, InsightsResponse> cache = new HashMap<>();

  /**
   * Enable cache only
   *
   * @param value True to enable cache only
   */
  public static void setCacheOnly(Boolean value) {
    cacheOnly = value;
  }

  /**
   * Clear insights cache
   *
   * <p>Intended for tests.
   */
  public static void cacheClear() {
    cache.clear();
  }

  /**
   * Cache and force a particular response for an IP address
   *
   * <p>This method can be used to cache a response for an IP address, which will be returned for an
   * insights query (instead of querying the actual API).
   *
   * <p>Intended for tests.
   *
   * @param ipAddress IP address
   * @param resourcePath Path to resource JSON file to use as response
   * @throws IOException IOException
   */
  @SuppressWarnings({"deprecation"})
  public static void cacheInsightsResource(String ipAddress, String resourcePath)
      throws IOException {
    InputStream in = Minfraud.class.getResourceAsStream(resourcePath);
    if (in == null) {
      throw new IOException("invalid resource path");
    }
    ObjectMapper o = new ObjectMapper();
    o.disable(MapperFeature.CAN_OVERRIDE_ACCESS_MODIFIERS);
    o.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    o.setDateFormat(new StdDateFormat().withColonInTimeZone(true));
    List<String> locales = Collections.singletonList("en");
    InjectableValues inj = new Std().addValue("locales", locales);
    InsightsResponse r = o.readerFor(InsightsResponse.class).with(inj).readValue(in);
    cache.put(ipAddress, r);
  }

  /**
   * Get Insights response from Minfraud using an IP address and an optional email address
   *
   * <p>See Maxmind's minfraud documentation for more details.
   *
   * @param ipAddress IP address string (required)
   * @param email email address string (optional)
   * @return {@link InsightsResponse} from Minfraud or null if an error occurred.
   */
  public InsightsResponse getInsights(String ipAddress, String email) {
    if (ipAddress == null) {
      return null;
    }

    if (cache.containsKey(ipAddress)) {
      return cache.get(ipAddress);
    }

    if (cacheOnly) {
      throw new RuntimeException(String.format("cache only with cache miss, %s", ipAddress));
    }

    Transaction.Builder txb;
    try {
      txb = new Transaction.Builder(new Device.Builder(InetAddress.getByName(ipAddress)).build());
    } catch (UnknownHostException exc) {
      return null;
    }

    if (email != null) {
      txb.email(new Email.Builder().address(email).build());
    }

    InsightsResponse resp;
    try {
      resp = mfClient.insights(txb.build());
    } catch (InsufficientFundsException exc) { // when there are insufficient funds on the account.
      log.error("InsufficientFundsException caught in getInsights(): {}", exc.getMessage());
      return null;
    } catch (AuthenticationException exc) { // when there is a problem authenticating.
      log.error("AuthenticationException caught in getInsights(): {}", exc.getMessage());
      return null;
    } catch (InvalidRequestException exc) { // when the request is invalid for some other reason.
      log.error("InvalidRequestException caught in getInsights(): {}", exc.getMessage());
      return null;
    } catch (PermissionRequiredException exc) { // when permission is required to use the service.
      log.error("PermissionRequiredException caught in getInsights(): {}", exc.getMessage());
      return null;
    } catch (MinFraudException exc) { // when the web service returns unexpected content.
      log.error(
          "MinFraudException caught in getInsights() - meaning the web service returned unexpected content: {}",
          exc.getMessage());
      return null;
    } catch (HttpException exc) { // when the web service returns an unexpected response.
      log.error(
          "HttpException caught in getInsights() - meaning the web service returned an unexpected response: {}",
          exc.getMessage());
      return null;
    } catch (IOException exc) { // when some other IO error occurs.
      log.error("IOException caught in getInsights(): {}", exc.getMessage());
      return null;
    }

    return resp;
  }

  /**
   * Create Minfraud client by passing in accountId and licenseKey.
   *
   * <p>Supports RuntimeSecrets
   *
   * @param accountId Minfraud Account ID
   * @param licenseKey Minfraud License Key
   * @param project GCP project name, only required if decrypting accountId or licenseKey via
   *     RuntimeSecrets
   */
  public Minfraud(String accountId, String licenseKey, String project) {
    log = LoggerFactory.getLogger(Minfraud.class);

    String accountIdDecrypted;
    try {
      accountIdDecrypted = RuntimeSecrets.interpretSecret(accountId, project);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    String licenseKeyDecrypted;
    try {
      licenseKeyDecrypted = RuntimeSecrets.interpretSecret(licenseKey, project);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    mfClient =
        new WebServiceClient.Builder(Integer.parseInt(accountIdDecrypted), licenseKeyDecrypted)
            .build();
  }

  /**
   * main routine can be used to fetch minfraud insights for an ip or email (or both) from the
   * command line
   *
   * @param args Command line arguments
   * @throws Exception Exception
   */
  public static void main(String[] args) throws Exception {
    Options options = new Options();

    Option accountid = new Option("a", "accountid", true, "Maxmind Account Id");
    accountid.setRequired(true);
    options.addOption(accountid);

    Option licensekey = new Option("l", "licensekey", true, "Maxmind License Key");
    licensekey.setRequired(true);
    options.addOption(licensekey);

    Option project = new Option("p", "project", true, "GCP Project name (if using RuntimeSecrets)");
    options.addOption(project);

    Option email = new Option("e", "email", true, "email to lookup");
    options.addOption(email);

    Option ip = new Option("i", "ip", true, "ip to lookup");
    options.addOption(ip);

    CommandLineParser parser = new DefaultParser();
    HelpFormatter fmt = new HelpFormatter();
    CommandLine cmd = null;
    try {
      cmd = parser.parse(options, args);
    } catch (ParseException e) {
      System.out.println(e.getMessage());
      fmt.printHelp("Minfraud", options);
      System.exit(1);
    }

    Minfraud mf =
        new Minfraud(
            cmd.getOptionValue("accountid"),
            cmd.getOptionValue("licensekey"),
            cmd.getOptionValue("project"));
    InsightsResponse resp =
        mf.getInsights(cmd.getOptionValue("ip", null), cmd.getOptionValue("email", null));
    System.out.println(resp);
  }
}
