module github.com/mozilla-services/foxsec-pipeline-contrib/auth0pull

go 1.12

require (
	cloud.google.com/go v0.36.0
	github.com/ajvb/auth0 v1.2.6-0.20190905170432-a56002e52dba
	github.com/aybabtme/iocontrol v0.0.0-20150809002002-ad15bcfc95a0 // indirect
	github.com/benbjohnson/clock v0.0.0-20161215174838-7dc76406b6d3 // indirect
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/sirupsen/logrus v1.4.2
	go.mozilla.org/mozlogrus v2.0.0+incompatible
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../
