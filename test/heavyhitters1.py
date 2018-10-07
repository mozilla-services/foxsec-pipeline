#!/usr/bin/env python3

import sys
from datetime import datetime, timedelta, timezone
from testlib.weblogclient import WebLogClient

testtimelen = 360
hhemitcount = 15

testdata = {}

def main():
    start = datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
    end = start + timedelta(seconds=testtimelen)
    while start < end:
        testdata[start] = []
        start = start + timedelta(seconds=1)

    clientsa = []
    clientsb = []
    clientsh = []
    for x in range(1, 11):
        clientsa.append(WebLogClient('192.168.1.' + str(x)))
    for x in range(11, 23):
        clientsb.append(WebLogClient('192.168.1.' + str(x)))
    for x in range(1, 3):
        clientsh.append(WebLogClient('10.0.0.' + str(x)).set_emitnumber(hhemitcount))

    cnt = 0
    clientset = clientsa
    for x in testdata.keys():
        if cnt >= testtimelen / 2:
            clientset = clientsb
        for client in clientset:
            client.emit(x)
        for client in clientsh:
            client.emit(x)
        cnt = cnt + 1

if __name__ == '__main__':
    main()
