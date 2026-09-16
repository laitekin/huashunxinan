package fingerprint

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestAcceptanceSample(t *testing.T) {
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
	expected := []Result{
		{IP: "1.2.3.4", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "8.9p1", OSHint: "Ubuntu", Confidence: 0.95},
		{IP: "1.2.3.5", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.24.0", Confidence: 0.9},
		{IP: "1.2.3.6", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.57", Confidence: 0.9},
		{IP: "1.2.3.7", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "8.0.32", Confidence: 0.9},
		{IP: "1.2.3.8", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.9", Port: 21, Protocol: "FTP", Product: "ProFTPD", Version: "1.3.7", Confidence: 0.9},
		{IP: "1.2.3.10", Port: 8080, Protocol: "HTTP", Product: "Jetty", Version: "9.4.51", Confidence: 0.85},
		{IP: "1.2.3.11", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "9.3", OSHint: "Debian", Confidence: 0.95},
		{IP: "1.2.3.12", Port: 80, Protocol: "HTTP", Product: "nginx", Version: "1.18.0", OSHint: "Ubuntu", Confidence: 0.9},
		{IP: "1.2.3.13", Port: 443, Protocol: "HTTP", Product: "Apache", Version: "2.4.41", OSHint: "Ubuntu", Confidence: 0.9},
		{IP: "1.2.3.14", Port: 3306, Protocol: "MySQL", Product: "MySQL", Version: "5.7.42", Confidence: 0.9},
		{IP: "1.2.3.15", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.16", Port: 21, Protocol: "FTP", Product: "vsFTPd", Version: "3.0.5", Confidence: 0.9},
		{IP: "1.2.3.17", Port: 8443, Protocol: "HTTP", Product: "nginx", Version: "1.25.3", Confidence: 0.9},
		{IP: "1.2.3.18", Port: 22, Protocol: "SSH", Product: "OpenSSH", Version: "4.3", Confidence: 0.95},
		{IP: "1.2.3.19", Port: 9999, Protocol: "unknown"},
		{IP: "1.2.3.20", Port: 8888, Protocol: "HTTP", Product: "Microsoft-IIS", Version: "10.0", Confidence: 0.9},
		{IP: "1.2.3.21", Port: 6379, Protocol: "Redis", Product: "Redis", Confidence: 0.7},
		{IP: "1.2.3.22", Port: 21, Protocol: "FTP", Product: "Pure-FTPd", Confidence: 0.9},
		{IP: "1.2.3.23", Port: 12345, Protocol: "unknown"},
	}
	if len(inputs) != len(expected) {
		t.Fatalf("sample count: got %d, want %d", len(inputs), len(expected))
	}
	for i, in := range inputs {
		got := engine.Identify(in)
		if !reflect.DeepEqual(got, expected[i]) {
			t.Errorf("sample %d:\n got  %+v\n want %+v", i+1, got, expected[i])
		}
	}
}

func TestRecognitionVariantsAndUnknowns(t *testing.T) {
	engine, err := Load("../../rules/fingerprints.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, banner, protocol, product, version string
		confidence                               float64
	}{
		{"case-insensitive HTTP header", "HTTP/1.1 200 OK\r\nsErVeR: nginx/1.27.2", "HTTP", "nginx", "1.27.2", 0.9},
		{"OpenSSH on an unrelated port", "SSH-2.0-OpenSSH_9.8p1", "SSH", "OpenSSH", "9.8p1", 0.95},
		{"generic SSH", "SSH-2.0-dropbear_2024.86", "SSH", "", "", 0.8},
		{"generic HTTP", "HTTP/1.0 503 Service Unavailable\r\nConnection: close", "HTTP", "", "", 0.75},
		{"Redis INFO", "# Server\r\nredis_version:7.2.5\r\nredis_mode:standalone", "Redis", "Redis", "7.2.5", 0.9},
		{"Redis unknown command", "-ERR unknown command 'COMMAND', with args beginning with:", "Redis", "Redis", "", 0.7},
		{"MariaDB compatibility prefix", "J\x00\x00\x00\x0a5.5.5-10.11.6-MariaDB-0+deb12u1\x00", "MySQL", "MariaDB", "10.11.6", 0.9},
		{"multiline ProFTPD greeting", "220-Welcome\r\n220 ProFTPD 1.3.8 Server ready", "FTP", "ProFTPD", "1.3.8", 0.9},
		{"Pure-FTPd without version", "220 Welcome to Pure-FTPd", "FTP", "Pure-FTPd", "", 0.9},
		{"generic FTP greeting", "220 FTP server ready", "FTP", "", "", 0.7},
		{"empty banner", "", "unknown", "", "", 0},
		{"product token without protocol evidence", "nginx/1.24.0", "unknown", "", "", 0},
		{"truncated MySQL packet", "J\x00\x00", "unknown", "", "", 0},
		{"opaque binary", "\x16\x03\x03\x00\x7a\x02\x00", "unknown", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Identify(Input{IP: "127.0.0.1", Port: 12345, Banner: tc.banner})
			if got.Protocol != tc.protocol || got.Product != tc.product || got.Version != tc.version || got.Confidence != tc.confidence {
				t.Errorf("got %+v", got)
			}
		})
	}
}
