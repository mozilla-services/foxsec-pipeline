FROM maven:latest

RUN export CLOUD_SDK_REPO="cloud-sdk-stretch" && \
    echo "deb http://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key add - && \
    apt-get update -y && apt-get install google-cloud-sdk -y

RUN apt-get install google-cloud-sdk-datastore-emulator memcached \
	net-tools netcat google-cloud-sdk-pubsub-emulator redis-server -y

RUN curl -OL https://dl.google.com/go/go1.11.1.linux-amd64.tar.gz && \
	tar -C /usr/local -zxf go1.11.1.linux-amd64.tar.gz && \
	mkdir -p /root/go && \
	env GOPATH=/root/go /usr/local/go/bin/go get -u go.mozilla.org/iprepd && \
	env GOPATH=/root/go /usr/local/go/bin/go install go.mozilla.org/iprepd/cmd/iprepd

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]
