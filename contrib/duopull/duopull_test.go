package duopull

import (
	"encoding/json"
	"testing"
)

var sample = []string{
	`{"path":"/admin/v1/logs/authentication","event":{"device":"Nexus 5 (000-000-0000)",
	"factor":"Duo Push","integration":"AWS SSH Access","ip":"127.0.0.1",
	"location":{"city":"San Francisco","country":"US","state":"California"},
	"new_enrollment":false,"reason":"User approved","result":"SUCCESS",
	"timestamp":1528920730,"username":"user1"}}`,
	`{"path":"/admin/v1/logs/authentication","event":{"device":"000-000-0000",
	"factor":"Duo Push","integration":"AWS SSH Access","ip":"127.0.0.1",
	"location":{"city":"San Francisco","country":"US","state":"California"},
	"new_enrollment":false,"reason":"User approved","result":"SUCCESS",
	"timestamp":1528921066,"username":"user2"}}`,
	`{"event":{"action":"admin_login","description":"{\"factor\": \"sms\", \"device\": \"000-000-0000\", \"primary_auth_method\": \"Password\", \"ip_address\": \"0.0.0.0\"}",
	"object":null,"timestamp":1530628619,
	"username":"Admin User"},"path":"/admin/v1/logs/administrator"}`,
}

var flattentest = []struct {
	data       string
	shouldFail bool
}{
	{`{"one": { "two": { "three": "four" }}}`, false},
	{`{"one": [ "two", "three", "four" ]}`, false},
	{`{"one": [ { "two": "three" }]}`, true},
	{`{"one": [ [ "two", "three" ]]}`, true},
}

func TestConvert(t *testing.T) {
	var v interface{}
	for _, x := range sample {
		err := json.Unmarshal([]byte(x), &v)
		if err != nil {
			t.Fatal(err)
		}
		ret, err := toMozLog(v)
		if err != nil {
			t.Fatal(err)
		}
		buf, err := json.Marshal(ret)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(string(buf))
	}
}

func TestFlatten(t *testing.T) {
	var v interface{}
	for _, x := range flattentest {
		err := json.Unmarshal([]byte(x.data), &v)
		if err != nil {
			t.Fatal(err)
		}
		in, ok := v.(map[string]interface{})
		if !ok {
			t.Fatal(err)
		}
		out := make(map[string]interface{})
		err = flatten(in, out, []string{})
		if x.shouldFail {
			if err == nil {
				t.Fatalf("flatten should have failed on %v", x.data)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
}
