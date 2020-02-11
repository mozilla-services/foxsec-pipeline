package main

import (
	"context"

	"github.com/mozilla-services/foxsec-pipeline/contrib/auth0pull"
)

func main() {
	err := auth0pull.Auth0Pull(context.Background(), auth0pull.PubSubMessage{})
	if err != nil {
		panic(err)
	}
}
