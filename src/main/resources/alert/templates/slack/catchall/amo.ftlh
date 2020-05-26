<#if category == "amo_cloud_submission">
${monitored_resource} cloud provider addon submission from ${sourceaddress}, guid <https://addons-internal.prod.mozaws.net/en-US/admin/models/addons/addon/${addon_guid}/change/|${addon_guid}> isapi ${addon_from_api} user_id <https://addons-internal.prod.mozaws.net/en-US/admin/models/users/userprofile/${addon_user_id}/change/|${addon_user_id}> (${alert.alertId})
</#if>
<#if category != "amo_cloud_submission">
${alert.summary}
</#if>
