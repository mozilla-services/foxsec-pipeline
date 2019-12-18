<#if auth_alert_type == "auth">
An authentication event for user ${username} was detected to access ${object} from ${sourceaddress} [${sourceaddress_city}/${sourceaddress_country}].
<#elseif auth_alert_type == "auth_session">
A sensitive event within ${object} was performed by user ${username} from ${sourceaddress} [${sourceaddress_city}/${sourceaddress_country}].
</#if>
<#if event_timestamp??>

This event occurred at ${event_timestamp}.
</#if>
<#if state_action_type??>
<#if state_action_type == "unknown_ip_within_geo">

The source address was new, however is near a previously known location so this message is informational.
<#elseif state_action_type == "unknown_ip_outside_geo">

The source address was new, and does not appear to be near any previously known location.
<#elseif state_action_type == "unknown_ip_hosting_provider">

The source address appears to be associated with a hosting provider.
<#elseif state_action_type == "unknown_ip_anon_network">

The source address appears to be associated with a known anonymity network.
</#if>
</#if>
<#if alert_notification_type??>
<#if alert_notification_type == "slack_confirmation">

If you have any questions about this alert, please refer to our user guide: ${doc_link}
<#elseif alert_notification_type == "slack_notification">

If this was not you, or you have any questions about this alert, email us at ${email_contact} with the alert id.

As well, you can refer to our user guide: ${doc_link}
</#if>
</#if>

alert id: ${alert.alertId}
