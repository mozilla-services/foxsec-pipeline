package com.mozilla.secops.gatekeeper;

import com.amazonaws.services.guardduty.model.Action;
import com.amazonaws.services.guardduty.model.AwsApiCallAction;
import com.amazonaws.services.guardduty.model.City;
import com.amazonaws.services.guardduty.model.Country;
import com.amazonaws.services.guardduty.model.DnsRequestAction;
import com.amazonaws.services.guardduty.model.DomainDetails;
import com.amazonaws.services.guardduty.model.Finding;
import com.amazonaws.services.guardduty.model.GeoLocation;
import com.amazonaws.services.guardduty.model.LocalPortDetails;
import com.amazonaws.services.guardduty.model.NetworkConnectionAction;
import com.amazonaws.services.guardduty.model.Organization;
import com.amazonaws.services.guardduty.model.PortProbeAction;
import com.amazonaws.services.guardduty.model.PortProbeDetail;
import com.amazonaws.services.guardduty.model.RemoteIpDetails;
import com.amazonaws.services.guardduty.model.RemotePortDetails;
import com.amazonaws.services.guardduty.model.Service;
import com.mozilla.secops.IOOptions;
import com.mozilla.secops.alert.Alert;
import com.mozilla.secops.alert.AlertSuppressor;
import com.mozilla.secops.identity.IdentityManager;
import com.mozilla.secops.parser.Event;
import com.mozilla.secops.parser.GuardDuty;
import com.mozilla.secops.parser.Payload;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import org.apache.beam.sdk.options.Default;
import org.apache.beam.sdk.options.Description;
import org.apache.beam.sdk.options.PipelineOptions;
import org.apache.beam.sdk.transforms.DoFn;
import org.apache.beam.sdk.transforms.PTransform;
import org.apache.beam.sdk.transforms.ParDo;
import org.apache.beam.sdk.values.KV;
import org.apache.beam.sdk.values.PCollection;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Implements various transforms on AWS GuardDuty {@link Finding} Events */
public class GuardDutyTransforms implements Serializable {
  private static final long serialVersionUID = 1L;

  /** Runtime options for GuardDuty Transforms */
  public interface Options extends PipelineOptions, IOOptions {
    @Description(
        "Ignore GuardDuty Findings for any finding types that match regex (multiple allowed)")
    String[] getIgnoreGDFindingTypeRegex();

    void setIgnoreGDFindingTypeRegex(String[] value);

    @Description(
        "Escalate GuardDuty Findings for any finding types that match regex (multiple allowed)")
    String[] getEscalateGDFindingTypeRegex();

    void setEscalateGDFindingTypeRegex(String[] value);

    @Default.Long(60 * 15) // 15 minutes
    @Description("Suppress alert generation for repeated GuardDuty Findings within this value")
    Long getAlertSuppressionSeconds();

    void setAlertSuppressionSeconds(Long value);
  }

  /** Extract GuardDuty Findings */
  public static class ExtractFindings extends PTransform<PCollection<Event>, PCollection<Event>> {
    private static final long serialVersionUID = 1L;

    private List<Pattern> exclude;

    /**
     * static initializer for filter
     *
     * @param opts {@link Options} pipeline options
     */
    public ExtractFindings(Options opts) {
      String[] ignoreRegexes = opts.getIgnoreGDFindingTypeRegex();
      exclude = new ArrayList<Pattern>();
      if (ignoreRegexes != null) {
        for (String s : ignoreRegexes) {
          exclude.add(Pattern.compile(s));
        }
      }
    }

    @Override
    public PCollection<Event> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, Event>() {
                private static final long serialVersionUID = 1L;

                @ProcessElement
                public void processElement(ProcessContext c) {
                  Event e = c.element();
                  if (!e.getPayloadType().equals(Payload.PayloadType.GUARDDUTY)) {
                    return;
                  }
                  GuardDuty gde = e.getPayload();
                  if (gde == null) {
                    return;
                  }
                  Finding f = gde.getFinding();
                  if (f == null || f.getType() == null) {
                    return;
                  }
                  for (Pattern p : exclude) {
                    if (p.matcher(f.getType()).matches()) {
                      return;
                    }
                  }
                  c.output(e);
                }
              }));
    }
  }

  /** Generate Alerts for relevant Findings */
  public static class GenerateAlerts extends PTransform<PCollection<Event>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;

    private static final String alertCategory = "gatekeeper:aws";

    private List<Pattern> escalate;
    private final String critNotifyEmail;
    private final String identityMgrPath;

    private Logger log;

    /**
     * static initializer for alert generation / escalation
     *
     * @param opts {@link Options} pipeline options
     */
    public GenerateAlerts(Options opts) {
      log = LoggerFactory.getLogger(GenerateAlerts.class);

      critNotifyEmail = opts.getCriticalNotificationEmail();
      identityMgrPath = opts.getIdentityManagerPath();

      String[] escalateRegexes = opts.getEscalateGDFindingTypeRegex();
      escalate = new ArrayList<Pattern>();
      if (escalateRegexes != null) {
        for (String s : escalateRegexes) {
          escalate.add(Pattern.compile(s));
        }
      } else {
        escalate.add(Pattern.compile(".+"));
      }
    }

    private void addBaseFindingData(Alert a, Finding f) {
      a.tryAddMetadata("aws_account", f.getAccountId());
      a.tryAddMetadata("aws_region", f.getRegion());
      a.tryAddMetadata("description", f.getDescription());
      Double severity = f.getSeverity();
      if (severity != null) {
        a.tryAddMetadata("finding_aws_severity", Double.toString(severity));
      }
      a.tryAddMetadata("finding_type", f.getType());
      a.tryAddMetadata("finding_id", f.getId());
      if (f.getAccountId() != null && f.getTitle() != null) {
        a.setSummary(
            String.format(
                "suspicious activity detected in aws account %s: %s",
                f.getAccountId(), f.getTitle()));
      }
      if (f.getUpdatedAt() != null) {
        a.setTimestamp(DateTime.parse(f.getUpdatedAt()));
      }
      a.setCategory(alertCategory);
      a.setSeverity(Alert.AlertSeverity.CRITICAL);
    }

    private void tryAddEscalationEmail(Alert a, Finding f) {
      if (critNotifyEmail != null && f.getType() != null) {
        for (Pattern p : escalate) {
          if (p.matcher(f.getType()).matches()) {
            a.addMetadata("notify_email_direct", critNotifyEmail);
            return;
          }
        }
      }
    }

    // best effort addition of local port related metadata
    private void tryAddLocalPortMetadata(Alert a, LocalPortDetails lpd) {
      if (lpd.getPort() != null) {
        a.tryAddMetadata("local_port", Integer.toString(lpd.getPort()));
      }
      a.tryAddMetadata("local_port_name", lpd.getPortName());
    }

    // best effort addition of remote ip related metadata
    private void tryAddRemoteIpMetadata(Alert a, RemoteIpDetails rid) {
      a.tryAddMetadata("remote_ip_address", rid.getIpAddressV4());
      Country country = rid.getCountry();
      if (country != null) {
        a.tryAddMetadata("remote_ip_country", country.getCountryName());
        a.tryAddMetadata("remote_ip_country_code", country.getCountryCode());
      }
      City city = rid.getCity();
      if (city != null) {
        a.tryAddMetadata("remote_ip_city", city.getCityName());
      }
      GeoLocation gl = rid.getGeoLocation();
      if (gl != null) {
        Double lat = gl.getLat();
        if (lat != null) {
          a.tryAddMetadata("remote_ip_latitude", Double.toString(lat));
        }
        Double lon = gl.getLon();
        if (lon != null) {
          a.tryAddMetadata("remote_ip_longitude", Double.toString(lon));
        }
      }
      Organization org = rid.getOrganization();
      if (org != null) {
        a.tryAddMetadata("remote_ip_asn", org.getAsn());
        a.tryAddMetadata("remote_ip_asn_org", org.getAsnOrg());
        a.tryAddMetadata("remote_ip_isp", org.getIsp());
        a.tryAddMetadata("remote_ip_org", org.getOrg());
      }
    }

    // best effort addition of network-connection (action) related metadata
    private void tryAddNetworkConnectionActionMetadata(Alert a, NetworkConnectionAction nca) {
      a.tryAddMetadata("network_connection_direction", nca.getConnectionDirection());
      a.tryAddMetadata("network_connection_proto", nca.getProtocol());
      a.tryAddMetadata("network_connection_blocked", Boolean.toString(nca.getBlocked()));
      LocalPortDetails lpd = nca.getLocalPortDetails();
      if (lpd != null) {
        tryAddLocalPortMetadata(a, lpd);
      }
      RemotePortDetails rpd = nca.getRemotePortDetails();
      if (rpd != null) {
        Integer rPort = rpd.getPort();
        if (rPort != null) {
          a.tryAddMetadata("remote_port", Integer.toString(rPort));
        }
        a.tryAddMetadata("remote_port_name", rpd.getPortName());
      }
      RemoteIpDetails rid = nca.getRemoteIpDetails();
      if (rid != null) {
        tryAddRemoteIpMetadata(a, rid);
      }
    }

    // best effort addition of aws-api-call (action) related metadata
    private void tryAddAwsApiCallActionMetadata(Alert a, AwsApiCallAction aca) {
      a.tryAddMetadata("api_name", aca.getApi());
      a.tryAddMetadata("api_service_name", aca.getServiceName());
      a.tryAddMetadata("api_caller_type", aca.getCallerType());
      DomainDetails dd = aca.getDomainDetails();
      if (dd != null) {
        a.tryAddMetadata("api_domain_name", dd.getDomain());
      }
      RemoteIpDetails rid = aca.getRemoteIpDetails();
      if (rid != null) {
        tryAddRemoteIpMetadata(a, rid);
      }
    }

    // best effort addition of dns-request (action) related metadata
    private void tryAddDnsRequestActionMetadata(Alert a, DnsRequestAction dra) {
      a.tryAddMetadata("domain_name", dra.getDomain());
    }

    // best effort addition of port-probe (action) related metadata
    private void tryAddPortProbeActionMetadata(Alert a, PortProbeAction ppa) {
      a.tryAddMetadata("port_probe_blocked", Boolean.toString(ppa.getBlocked()));
      List<PortProbeDetail> ppdlist = ppa.getPortProbeDetails();
      if (ppdlist != null && ppdlist.size() > 0) {
        // Note that schema allows repeated metadata keys
        for (PortProbeDetail ppd : ppdlist) {
          RemoteIpDetails rid = ppd.getRemoteIpDetails();
          if (rid != null) {
            tryAddRemoteIpMetadata(a, rid);
          }
          LocalPortDetails lpd = ppd.getLocalPortDetails();
          if (rid != null) {
            tryAddLocalPortMetadata(a, lpd);
          }
        }
      }
    }

    /**
     * adds informational metadata using values within finding without assuming a particular finding
     * type - adds all metadata that is available
     *
     * @param a {@link Alert} the target alert
     * @param f {@link Finding} the source finding
     */
    private void addTypeSpecificFindingData(Alert a, Finding f) {
      Service svc = f.getService();
      if (svc != null) {
        a.tryAddMetadata("aws_service", svc.getServiceName());
        a.tryAddMetadata("aws_gd_detector_id", svc.getDetectorId());
        Integer count = svc.getCount();
        if (count != null) {
          a.tryAddMetadata("finding_count", Integer.toString(count));
        }
        a.tryAddMetadata("finding_first_seen_at", svc.getEventFirstSeen());
        a.tryAddMetadata("finding_last_seen_at", svc.getEventLastSeen());
        Action ac = svc.getAction();
        if (ac != null) {
          a.tryAddMetadata("finding_action", ac.getActionType());
          NetworkConnectionAction nca = ac.getNetworkConnectionAction();
          if (nca != null) {
            tryAddNetworkConnectionActionMetadata(a, nca);
          }
          AwsApiCallAction aca = ac.getAwsApiCallAction();
          if (aca != null) {
            tryAddAwsApiCallActionMetadata(a, aca);
          }
          DnsRequestAction dra = ac.getDnsRequestAction();
          if (dra != null) {
            tryAddDnsRequestActionMetadata(a, dra);
          }
          PortProbeAction ppa = ac.getPortProbeAction();
          if (ppa != null) {
            tryAddPortProbeActionMetadata(a, ppa);
          }
        }
      }
    }

    @Override
    public PCollection<Alert> expand(PCollection<Event> input) {
      return input.apply(
          ParDo.of(
              new DoFn<Event, Alert>() {
                private static final long serialVersionUID = 1L;

                private Map<String, String> awsAcctMap;

                private void tryAddAccountName(Alert a) {
                  if (awsAcctMap != null) {
                    String acctId = a.getMetadataValue("aws_account");
                    if (acctId != null) {
                      String acctName = awsAcctMap.get(acctId);
                      if (acctName != null) {
                        a.addMetadata("aws_account_name", acctName);
                        return;
                      }
                    }
                  }
                }

                @Setup
                public void setup() {
                  if (identityMgrPath != null) {
                    try {
                      awsAcctMap = IdentityManager.load(identityMgrPath).getAwsAccountMap();
                      if (awsAcctMap != null) {
                        log.info("aws account map successfully loaded from identity manager file");
                      } else {
                        log.warn(
                            "no aws account map contained in identity manager file, alerts will not contain aws_account_name");
                      }
                    } catch (IOException x) {
                      log.error(
                          "failed to load identity manager, alerts will not contain aws_account_name. error: {}",
                          x.getMessage());
                    }
                  } else {
                    log.warn(
                        "no identity manager provided, alerts will not contain aws_account_name");
                  }
                }

                @ProcessElement
                public void processElement(ProcessContext c) {
                  Event e = c.element();
                  if (!e.getPayloadType().equals(Payload.PayloadType.GUARDDUTY)) {
                    return;
                  }
                  GuardDuty gd = e.getPayload();
                  if (gd == null) {
                    return;
                  }
                  Finding f = gd.getFinding();
                  if (f == null) {
                    return;
                  }

                  Alert a = new Alert();

                  addBaseFindingData(a, f);
                  addTypeSpecificFindingData(a, f);
                  tryAddEscalationEmail(a, f);
                  tryAddAccountName(a);
                  c.output(a);
                }
              }));
    }
  }

  /**
   * Suppress Alerts for repeated GuardDuty Findings.
   *
   * <p>A "repeated finding" in GuardDuty means the same (potential) bad actor is performing the
   * same action against the same resource in your AWS environment. Findings are uniquely identified
   * by their "id".
   *
   * <p>GuardDuty has a built-in setting to avoid emitting a new CloudWatch event for repeated
   * findings within a certain window of time. Valid values for that window are 15 minutes, 1 hour,
   * or 6 hours (default).
   * https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_cloudwatch.html#guardduty_findings_cloudwatch_notification_frequency
   *
   * <p>This transform adds a second layer of protection against generation of alerts for repeated
   * findings
   */
  public static class SuppressAlerts extends PTransform<PCollection<Alert>, PCollection<Alert>> {
    private static final long serialVersionUID = 1L;
    private static final String suppressionStateMetadataKey = "finding_id";

    private static Long alertSuppressionWindow;

    /**
     * static initializer for alert suppression
     *
     * @param opts {@link Options} pipeline options
     */
    public SuppressAlerts(Options opts) {
      alertSuppressionWindow = opts.getAlertSuppressionSeconds();
    }

    @Override
    public PCollection<Alert> expand(PCollection<Alert> input) {
      return input
          .apply(
              ParDo.of(
                  new DoFn<Alert, KV<String, Alert>>() {
                    private static final long serialVersionUID = 1L;

                    @ProcessElement
                    public void processElement(ProcessContext c) {
                      Alert a = c.element();
                      if (a == null || a.getMetadataValue(suppressionStateMetadataKey) == null) {
                        return;
                      }
                      c.output(KV.of(a.getMetadataValue(suppressionStateMetadataKey), a));
                    }
                  }))
          .apply(ParDo.of(new AlertSuppressor(alertSuppressionWindow)));
    }
  }
}
