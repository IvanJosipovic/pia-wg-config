package pia

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func TestAvailableRegionsPortForwarding(t *testing.T) {
	const response = `{
		"regions": [
			{
				"id": "ca_vancouver",
				"name": "CA Vancouver",
				"port_forward": true,
				"servers": {"wg": [{"cn": "Server-1", "ip": "192.0.2.1"}]}
			},
			{
				"id": "us_california",
				"name": "US California",
				"port_forward": false,
				"servers": {"wg": [{"cn": "Server-2", "ip": "192.0.2.2"}]}
			},
			{
				"id": "offline",
				"name": "Offline",
				"port_forward": true,
				"offline": true,
				"servers": {"wg": [{"cn": "Server-3", "ip": "192.0.2.3"}]}
			},
			{
				"id": "no-wireguard",
				"name": "No WireGuard",
				"port_forward": true,
				"servers": {"wg": []}
			}
		]
	}`

	var serverList piaServerList
	if err := json.Unmarshal([]byte(response), &serverList); err != nil {
		t.Fatalf("unmarshal server list: %v", err)
	}

	regions := availableRegionsFromServerList(serverList)
	if len(regions) != 2 {
		t.Fatalf("got %d available regions, want 2", len(regions))
	}
	if !regions["ca_vancouver"].PortForward {
		t.Error("ca_vancouver should support port forwarding")
	}
	if regions["ca_vancouver"].Name != "CA Vancouver" {
		t.Errorf("ca_vancouver name = %q, want %q", regions["ca_vancouver"].Name, "CA Vancouver")
	}
	if regions["us_california"].PortForward {
		t.Error("us_california should not support port forwarding")
	}
	if _, ok := regions["offline"]; ok {
		t.Error("offline region should not be listed")
	}
	if _, ok := regions["no-wireguard"]; ok {
		t.Error("region without WireGuard servers should not be listed")
	}
}

// TestEmbeddedCACert pins the embedded PIA CA so it cannot be swapped silently.
func TestEmbeddedCACert(t *testing.T) {
	const wantSHA256 = "1fd25658456eab3041fba77ccd398ab8124edcc1b8b2fc1d55fdf6b1bbfc9d70"

	block, rest := pem.Decode(piaCACert)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatal("embedded CA is not a PEM certificate")
	}
	if extra, _ := pem.Decode(rest); extra != nil {
		t.Fatal("embedded CA contains more than one PEM block")
	}

	sum := sha256.Sum256(block.Bytes)
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		t.Fatalf("embedded CA SHA-256 = %s, want %s", got, wantSHA256)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse embedded CA: %v", err)
	}
	if !cert.IsCA {
		t.Fatal("embedded certificate is not a CA")
	}
}

// TestExecutePIARequestErrorOmitsToken checks that a failed addKey request
// does not leak the token (carried in the URL query) through the error.
func TestExecutePIARequestErrorOmitsToken(t *testing.T) {
	const token = "SECRET-TOKEN-VALUE"
	p := &PIAClient{}
	server := Server{Cn: "Server-1-0a", IP: "127.0.0.1"}

	// Port 1 on localhost is closed, so the dial fails.
	resp, err := p.executePIARequest(server, "https://Server-1-0a:1/addKey?pt="+token+"&pubkey=x")
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("error leaks the token: %v", err)
	}
	if !strings.Contains(err.Error(), server.Cn) {
		t.Fatalf("error should name the server: %v", err)
	}
}
