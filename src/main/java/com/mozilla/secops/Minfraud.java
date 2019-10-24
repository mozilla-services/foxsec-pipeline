package com.mozilla.secops;

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
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Minfraud implements Serializable {
  private static final long serialVersionUID = 1L;
  private final Logger log;
  private WebServiceClient mfClient;

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
   */
  public Minfraud(String accountId, String licenseKey) {
    log = LoggerFactory.getLogger(Minfraud.class);

    String accountIdDecrypted;
    try {
      accountIdDecrypted = RuntimeSecrets.interpretSecret(accountId, null);
    } catch (IOException exc) {
      throw new RuntimeException(exc.getMessage());
    }

    String licenseKeyDecrypted;
    try {
      licenseKeyDecrypted = RuntimeSecrets.interpretSecret(licenseKey, null);
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
   */
  public static void main(String[] args) throws Exception {
    Options options = new Options();

    Option accountid = new Option("a", "accountid", true, "Maxmind Account Id");
    accountid.setRequired(true);
    options.addOption(accountid);

    Option licensekey = new Option("l", "licensekey", true, "Maxmind License Key");
    licensekey.setRequired(true);
    options.addOption(licensekey);

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

    Minfraud mf = new Minfraud(cmd.getOptionValue("accountid"), cmd.getOptionValue("licensekey"));
    InsightsResponse resp =
        mf.getInsights(cmd.getOptionValue("ip", null), cmd.getOptionValue("email", null));
    System.out.println(resp);
  }
}
