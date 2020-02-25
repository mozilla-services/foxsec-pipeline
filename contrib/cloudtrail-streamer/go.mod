module github.com/mozilla-services/foxsec-pipeline/contrib/cloudtrail-streamer

go 1.13

require (
	cloud.google.com/go v0.43.0
	cloud.google.com/go/logging v1.0.0
	github.com/aws/aws-lambda-go v1.2.0
	github.com/aws/aws-sdk-go v1.23.13
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/mozlog v0.0.0-20170222151521-4bb13139d403 // indirect
	go.mozilla.org/mozlogrus v1.0.0
	go.mozilla.org/sops/v3 v3.5.0
	google.golang.org/api v0.7.0
)
