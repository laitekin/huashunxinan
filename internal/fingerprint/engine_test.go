package fingerprint

import (
	"encoding/json"
	"os"
	"testing"
)

func TestSample(t *testing.T) {
	engine, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../data/sample.json")
	if err != nil {
		t.Fatal(err)
	}
	var inputs []Input
	if err := json.Unmarshal(data, &inputs); err != nil {
		t.Fatal(err)
	}
	expected := []string{"SSH", "HTTP", "HTTP", "MySQL", "Redis", "FTP", "HTTP", "SSH", "HTTP", "HTTP", "MySQL", "Redis", "FTP", "HTTP", "SSH", "unknown", "HTTP", "Redis", "FTP", "unknown"}
	if len(inputs) != len(expected) {
		t.Fatal("sample count")
	}
	for i, in := range inputs {
		got := engine.Identify(in)
		if got.Protocol != expected[i] {
			t.Errorf("sample %d: %+v", i, got)
		}
	}
	first := engine.Identify(inputs[0])
	if first.Product != "OpenSSH" || first.Version != "8.9p1" || first.OSHint != "Ubuntu" {
		t.Fatalf("SSH detail: %+v", first)
	}
	mysql := engine.Identify(inputs[3])
	if mysql.Version != "8.0.32" {
		t.Fatalf("MySQL detail: %+v", mysql)
	}
}

func TestContentRatherThanPort(t *testing.T) {
	engine, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ banner, protocol, product, version string }{
		{"HTTP/1.1 200 OK\r\nsErVeR: nginx/1.27.2", "HTTP", "nginx", "1.27.2"},
		{"SSH-2.0-OpenSSH_9.8p1", "SSH", "OpenSSH", "9.8p1"},
		{"220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", ""},
		{"", "unknown", "", ""},
		{"nginx/1.24.0", "unknown", "", ""},
		{"J\x00\x00", "unknown", "", ""},
	} {
		got := engine.Identify(Input{IP: "127.0.0.1", Port: 12345, Banner: tc.banner})
		if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version {
			t.Errorf("%q: %+v", tc.banner, got)
		}
	}
}
