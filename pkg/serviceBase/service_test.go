package serviceBase

import (
	"testing"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/spf13/viper"
)

func TestResolveListenConfiguration(t *testing.T) {
	tests := []struct {
		name                  string
		configuredAddress     string
		portOverride          string
		expectedAddress       string
		expectedScheme        string
		expectedServerAddress string
		expectedLoopback      bool
		expectError           bool
	}{
		{
			name:                  "localhost HTTPS",
			configuredAddress:     "https://localhost:8881",
			expectedAddress:       "https://localhost:8881",
			expectedScheme:        "https",
			expectedServerAddress: "localhost:8881",
			expectedLoopback:      true,
		},
		{
			name:                  "IPv4 loopback",
			configuredAddress:     "http://127.0.0.1:8881",
			expectedAddress:       "http://127.0.0.1:8881",
			expectedScheme:        "http",
			expectedServerAddress: "127.0.0.1:8881",
			expectedLoopback:      true,
		},
		{
			name:                  "IPv6 loopback",
			configuredAddress:     "http://[::1]:8881",
			expectedAddress:       "http://[::1]:8881",
			expectedScheme:        "http",
			expectedServerAddress: "[::1]:8881",
			expectedLoopback:      true,
		},
		{
			name:                  "misleading localhost hostname",
			configuredAddress:     "https://localhost.example.com:8881",
			expectedAddress:       "https://localhost.example.com:8881",
			expectedScheme:        "https",
			expectedServerAddress: "localhost.example.com:8881",
			expectedLoopback:      false,
		},
		{
			name:                  "Cloud Run PORT override",
			configuredAddress:     "https://localhost:8881",
			portOverride:          "8080",
			expectedAddress:       "http://0.0.0.0:8080",
			expectedScheme:        "http",
			expectedServerAddress: "0.0.0.0:8080",
			expectedLoopback:      false,
		},
		{
			name:              "missing port",
			configuredAddress: "https://localhost",
			expectError:       true,
		},
		{
			name:              "invalid scheme",
			configuredAddress: "ftp://localhost:8881",
			expectError:       true,
		},
		{
			name:              "address contains path",
			configuredAddress: "https://localhost:8881/fake",
			expectError:       true,
		},
		{
			name:              "invalid PORT override",
			configuredAddress: "https://localhost:8881",
			portOverride:      "bogus",
			expectError:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("PORT", test.portOverride)

			configuration := viper.New()
			configuration.Set(
				constants.LISTEN_ADDRESS,
				test.configuredAddress,
			)

			address,
				scheme,
				serverAddress,
				loopback,
				err := resolveListenConfiguration(configuration)

			if test.expectError {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if address != test.expectedAddress {
				t.Errorf(
					"expected address %q, got %q",
					test.expectedAddress,
					address,
				)
			}
			if scheme != test.expectedScheme {
				t.Errorf(
					"expected scheme %q, got %q",
					test.expectedScheme,
					scheme,
				)
			}
			if serverAddress != test.expectedServerAddress {
				t.Errorf(
					"expected server address %q, got %q",
					test.expectedServerAddress,
					serverAddress,
				)
			}
			if loopback != test.expectedLoopback {
				t.Errorf(
					"expected loopback %t, got %t",
					test.expectedLoopback,
					loopback,
				)
			}
		})
	}
}
