#!/usr/bin/env python3

import sys
from datetime import datetime, timedelta, timezone
from testlib.weblogclient import WebLogClient

testtimelen = 360

testdata = {}

def main():
    start = datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
    end = start + timedelta(seconds=testtimelen)
    while start < end:
        testdata[start] = []
        start = start + timedelta(seconds=1)

    clientsa = []
    clientserr = []
    for x in range(1, 11):
        clientsa.append(WebLogClient('192.168.1.' + str(x)))
    for x in range(1, 3):
        clientserr.append(WebLogClient('10.0.0.' + str(x)).set_statuscode(404))

    for x in testdata.keys():
        for client in clientsa:
            client.emit(x)
        for client in clientserr:
            client.emit(x)

if __name__ == '__main__':
    main()
