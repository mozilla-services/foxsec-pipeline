package main

import (
	"net/http"

	"github.com/mozilla-services/foxsec-pipeline-contrib/slackbot-http"
)

func main() {
	http.HandleFunc("/", slackbothttp.SlackbotHTTP)
	http.ListenAndServe(":8888", nil)
}
