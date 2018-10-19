#!/usr/bin/env python3

import json
import sys

class WebLogClient:
    OUTPUT_STACKDRIVER = 1

    STACKDRIVERTEMPLATE = '''
{"httpRequest":{"referer":"https://send.firefox.com/","remoteIp":"127.0.0.1","requestMethod":"GET",
"requestSize":"43","requestUrl":"https://send.firefox.com/public/locales/en-US/send.js",
"responseSize":"2692","serverIp":"10.8.0.3","status":200,"userAgent":"Mozilla"},
"insertId":"AAAAAAAAAAAAAAA",
"jsonPayload":{"@type":"type.googleapis.com/google.cloud.loadbalancing.type.LoadBalancerLogEntry",
"statusDetails":"response_sent_by_backend"},"logName":"projects/test/logs/requests",
"receiveTimestamp":"2018-09-28T18:55:12.840306467Z","resource":{"labels":{"backend_service_name":"",
"forwarding_rule_name":"prod-send","project_id":"test","target_proxy_name":"prod-send",
"url_map_name":"prod-send","zone":"global"},"type":"http_load_balancer"},"severity":"INFO",
"spanId":"AAAAAAAAAAAAAAAA","timestamp":"2018-09-28T18:55:12.469373944Z",
"trace":"projects/test/traces/00000000000000000000000000000000"}
'''

    def __init__(self, ip):
        self._emitnumber = 1
        self._status = 200
        self._ip = ip
        self._output = self.OUTPUT_STACKDRIVER

    def set_emitnumber(self, x):
        self._emitnumber = x
        return self

    def set_statuscode(self, x):
        self._status = x
        return self

    def emit_stackdriver(self, ts):
        buf = json.loads(self.STACKDRIVERTEMPLATE)
        buf['httpRequest']['remoteIp'] = self._ip
        buf['httpRequest']['status'] = self._status
        buf['timestamp'] = ts.isoformat()
        for x in range(self._emitnumber):
            sys.stdout.write(json.dumps(buf) + '\n')

    def emit(self, ts):
        if self._output == self.OUTPUT_STACKDRIVER:
            self.emit_stackdriver(ts)
        else:
            raise ValueError('no output mode set')
