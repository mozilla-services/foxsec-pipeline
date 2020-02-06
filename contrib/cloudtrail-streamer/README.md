# Lambda Function for Cloudtrail to Kinesis streaming

This is a Lambda function that will stream Cloudtrail logs saved to an S3 bucket to
either a single Kinesis stream, a single GCP PubSub topic, a single GCP Stackdriver log
stream, or any combination of the three.

It can support any number of S3 buckets, as it executes based off of any S3 notification
events sent either directly to the lambda func or to an SNS topic that the lambda func subscribes
to, but the code is specific to Cloudtrail logs. It will decode
the Cloudtrail JSON and send one "Record" at a time to the kinesis stream.

Any single lambda function running this code can only support EITHER S3 events or SNS events.
This is controlled by the `CT_EVENT_TYPE` environment variable, and defaults to S3.

## Lambda Packaging

`make package` can be used to package the function in a zip file. A docker container is
temporarily used to generate the Linux executable and archive it in the zip.

## Deployment

An example CloudFormation template exists in the [cf](./cf) directory. This will
create everything needed for the lambda function to function as well as a mock s3
bucket and kinesis stream that can be used for testing.

#### A note on GCP configuration

If you want to send Cloudtrail records to GCP's PubSub or GCP's Stackdriver (or both), you will need to additionally
provide a JSON file in the Lambda code bundle named `gcp_credentials.json` that holds the Service Account credentials
that will be used to publish to the configured topic or write to the configured log stream.

We support (and recommend) using [sops](https://github.com/mozilla/sops) to encrypt this JSON blob.

### Environment Variables

#### CT_STACKDRIVER_NAME (required if neither CT_TOPIC_ID or CT_KINESIS_STREAM are set)

The name of the Stackdriver logger that Cloudtrail records will be sent to.

Example: `CT_STACKDRIVER_NAME="cloudtrail-streamer"`

#### CT_TOPIC_ID (required if neither CT_STACKDRIVER_NAME or CT_KINESIS_STREAM are set)

The topic id of the GCP PubSub topic that Cloudtrail records will be pushed to.

Example: `CT_TOPIC_ID="cloudtrail-streamer"`

#### CT_PROJECT_ID (required if CT_TOPIC_ID is set)

The id of the GCP project that holds the PubSub topic that Cloudtrail records will be pushed to.

Example: `CT_PROJECT_ID="my-gcp-project"`

#### CT_KINESIS_STREAM (required if neither CT_STACKDRIVER_NAME or CT_TOPIC_ID are set)

The name of the Kinesis stream that Cloudtrail records will be pushed to.

Example: `CT_KINESIS_STREAM="cloudtrail-streamer"`

#### CT_KINESIS_REGION (required if CT_KINESIS_STREAM is set)

The region that the Kinesis stream lives in.

Example: `CT_KINESIS_REGION="us-west-2"`

#### CT_S3_ROLE_ARN (optional)

Role to assume for use by the s3 client.

Useful when this Lambda function and the S3 bucket with CloudTrail logs are in different AWS accounts.

Example: `CT_S3_ROLE_ARN="arn:aws:iam::555555555555:role/CloudtrailGetObjectRole"`

#### CT_EVENT_TYPE (optional)

The type of event that will be sent to the Lambda function. Default is `CT_EVENT_TYPE="S3"`.

To use the SNS event handler, set `CT_EVENT_TYPE="SNS"`.

#### CT_DEBUG_LOGGING (optional)

Setting `CT_DEBUG_LOGGING=1` will enable debug logging within the handler.

#### CT_KINESIS_BATCH_SIZE (optional)

The number of records in a batched put to the Kinesis stream.

By default, `CT_KINESIS_BATCH_SIZE` is set to `500` (which is the max allowed).

#### CT_EVENT_FILTERS (optional)

Comma-separated list of `eventSource:eventName` that will be filtered out.

Example: `CT_EVENT_FILTERS="kinesis:DescribeStream,elasticmapreduce:ListClusters"`

## References

The structure of this project is based off of this AWS tutorial:
https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html
