FROM maven:latest

RUN export CLOUD_SDK_REPO="cloud-sdk-stretch" && \
    echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    apt-get update -y && apt-get install google-cloud-sdk -y

RUN apt-get install google-cloud-sdk-datastore-emulator memcached \
	net-tools netcat google-cloud-sdk-pubsub-emulator -y

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
