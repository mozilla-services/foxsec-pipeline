module github.com/mozilla-services/foxsec-pipeline-contrib/auth0pull/cmd

go 1.12

require (
	github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0
	github.com/mozilla-services/foxsec-pipeline-contrib/auth0pull v0.0.0
)

replace github.com/mozilla-services/foxsec-pipeline-contrib v0.0.0 => ../../

replace github.com/mozilla-services/foxsec-pipeline-contrib/auth0pull v0.0.0 => ../
