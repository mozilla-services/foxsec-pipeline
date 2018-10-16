#!/bin/bash

set -e

gcloud config set project foxsec-pipeline
nohup gcloud beta emulators datastore start >/dev/null 2>&1 &
nohup gcloud beta emulators pubsub start >/dev/null 2>&1 &
while ! nc -z localhost 8081; do sleep 0.1; done
while ! nc -z localhost 8085; do sleep 0.1; done

/usr/bin/memcached -u root -d
/usr/bin/redis-server --daemonize yes
while ! nc -z localhost 11211; do sleep 0.1; done
while ! nc -z localhost 6379; do sleep 0.1; done

nohup /root/go/bin/iprepd -c /etc/iprepd/iprepd.yaml >/dev/null 2>&1 &
while ! nc -z localhost 8080; do sleep 0.1; done

exec "$@"
