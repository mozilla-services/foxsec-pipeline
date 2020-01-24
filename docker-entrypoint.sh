#!/bin/bash

set -e

# If the WITHOUT_DAEMONS environment variable is not set, start the daemons
# we need to run tests. WITHOUT_DAEMONS should be non-null if the image is
# being executed to for example deploy pipelines for production.
if [[ -z "$WITHOUT_DAEMONS" ]]; then
	gcloud config set project foxsec-pipeline
	setsid nohup gcloud beta emulators datastore start >/var/log/datastore.out 2>&1 &
	setsid nohup gcloud beta emulators pubsub start >/var/log/pubsub.out 2>&1 &
	while ! nc -z localhost 8081; do sleep 0.1; done
	while ! nc -z localhost 8085; do sleep 0.1; done

	/usr/bin/memcached -u root -d
	/usr/bin/redis-server --daemonize yes
	while ! nc -z localhost 11211; do sleep 0.1; done
	while ! nc -z localhost 6379; do sleep 0.1; done

	nohup /root/go/bin/iprepd -c /etc/iprepd/iprepd.yaml >/dev/null 2>&1 &
	while ! nc -z localhost 8080; do sleep 0.1; done
fi

exec "$@"
