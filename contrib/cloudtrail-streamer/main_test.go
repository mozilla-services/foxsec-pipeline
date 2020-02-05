package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go/service/s3"
)

var testData = []byte(`
	{"Records": [
		{"foo": "bar"},
		{"key": {"subkey": "value"}}
	]}
`)

type BufferCloser struct {
	*bytes.Buffer
}

func (bc BufferCloser) Close() error {
	return nil
}

func TestReadLogFile(t *testing.T) {
	// Setup
	buf := BufferCloser{&bytes.Buffer{}}
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(testData)
	if err != nil {
		t.Fatal(err)
	}
	zw.Close()

	// Test
	cntType := "application/x-gzip"
	obj := &s3.GetObjectOutput{Body: buf, ContentType: &cntType}

	logFile, err := readLogFile(obj)
	if err != nil {
		t.Fatal(err)
	}

	if len(logFile.Records) != 2 {
		t.Fatal("Parsing error, len(logFile.Records) != 2")
	}

	encodedRecord, err := json.Marshal(logFile.Records[0])
	if err != nil {
		t.Fatal(err)
	}

	if string(encodedRecord) != `{"foo":"bar"}` {
		t.Fatal("Incorrectly parsed record.")
	}
}

var testFilters = "kinesis:DescribeStream,elasticmapreduce:ListClusters"
var testBadFilters = "kinesisDescribeStream,foo:bar:,elasticmapreduce:ListClusters"

func TestParseFilters(t *testing.T) {
	eventFilters := parseFilters(testFilters)

	if len(eventFilters) != 2 {
		t.Fatal("Parsing erroring, len(eventFilters) != 2")
	}
	if eventFilters[0].EventSource != "kinesis.amazonaws.com" {
		t.Fatal("Parsing error, eventFilters[0].EventSource != kinesis.amazonaws.com")
	}

	eventFiltersWithBad := parseFilters(testBadFilters)

	if len(eventFiltersWithBad) != 1 {
		t.Fatal("Parsing erroring, len(eventFiltersWithBad) != 1")
	}

	if eventFiltersWithBad[0].EventSource != "elasticmapreduce.amazonaws.com" {
		t.Fatal("Parsing error, eventFiltersWithBad[0].EventSource != elasticmapreduce.amazonaws.com")
	}

	if eventFiltersWithBad[0].EventName != "ListClusters" {
		t.Fatal("Parsing error, eventFiltersWithBad[0].EventName != ListClusters")
	}
}
