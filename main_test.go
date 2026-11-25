package main

import "testing"

func TestValidatePortForwarding(t *testing.T) {
	tests := []struct {
		name      string
		required  bool
		supported bool
		wantError bool
	}{
		{name: "not required", required: false, supported: false},
		{name: "required and supported", required: true, supported: true},
		{name: "required but unsupported", required: true, supported: false, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePortForwarding("us_california", tt.required, tt.supported)
			if (err != nil) != tt.wantError {
				t.Fatalf("validatePortForwarding() error = %v, wantError %t", err, tt.wantError)
			}
		})
	}
}
