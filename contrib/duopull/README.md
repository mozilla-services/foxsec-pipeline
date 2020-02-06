# Cloud Function for Duo Log Collection

This is a Cloud function that pulls administration/authentication/telephony logs
from the Duo API and pushes them into a logging pipeline via Stackdriver.

## Basic operation

The function stores state information in Datastore. The state information is essentially
timestamp data indicating when the last log message from the API was collected, so the
function knows when to begin requesting logs from for the next period. After the function runs
it updates the state data for the next iteration.

When log data is read, it is written to Stackdriver.

## Deployment

### GCP Cloud Function Environment

The following settings are required for deployment.

#### KMS_KEYNAME

The Cloud KMS key name to use to try and decrypt IKEY and SKEY.

#### DUOPULL_HOST

The Duo admin API host requests for logs will be made to.

#### DUOPULL_IKEY

The authentication identity to be used for API requests.

#### DUOPULL_SKEY

The secret key to be used for API requests.

## Development

### Running locally

`go run cmd/main.go`

### Environment

#### GCP_PROJECT

`GCP_PROJECT` is set automatically by GCP when you deploy it as a Cloud Function, but if you want to test
Datastore or Stackdriver locally, you will need to set it.

#### DEBUGGCP

If the DEBUGGCP environment variable is set to `1`, the function will generate mock events and make
requests to `https://www.mozilla.org` instead of the actual Duo API to confirm outbound
connectivity from the function. In this mode the function will update the state in datastore and send
events to Stackdriver but will not make requests to the actual Duo API.

#### DEBUGDUO

In this mode the function will not execute as a Cloud Function but will poll the Duo API for log data,
write the data to stdout and exit. The DEBUGDUO environment variable should be set to `1` to
enable this mode.
