module github.com/mozilla-services/foxsec-pipeline/contrib/slackbot-http

require (
	cloud.google.com/go/pubsub v1.2.0
	github.com/gorilla/websocket v1.4.0 // indirect
	github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0
	github.com/nlopes/slack v0.6.0
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.4.0
	go.mozilla.org/mozlogrus v2.0.0+incompatible
	golang.org/x/exp v0.0.0-20200207192155-f17229e696bd // indirect
	golang.org/x/tools v0.0.0-20200211183705-e2a38c836335 // indirect
	google.golang.org/api v0.17.0 // indirect
	google.golang.org/genproto v0.0.0-20200211111953-2dc5924e3898 // indirect
	google.golang.org/grpc v1.27.1 // indirect
)

replace github.com/mozilla-services/foxsec-pipeline/contrib v0.0.0 => ../

go 1.13
