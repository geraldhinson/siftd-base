package unittests

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	shared "github.com/geraldhinson/siftd-base/pkg/unitTestsShared"
)

func TestServiceBase_InstantiateAndCalls(t *testing.T) {
	router, err := shared.NewTestRouter(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}

	t.Run("GET request", func(t *testing.T) {
		// TestServiceBase_BadParam
		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, nil, "GUID-fake-member-GUID", "AgeOver=bogus-number")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		}
		if body == nil {
			t.Fatalf("Expected nil body, got %s", string(body))
		}

		// TestServiceBase_GoodParamNoneFound
		body, err, status = shared.CallNounRouterViaLoopback(router.Configuration, nil, "GUID-fake-member-GUID", "AgeOver=40")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))
			var resources []shared.TestNounResource
			err = json.Unmarshal(body, &resources)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}
			// check length of resource array
			if len(resources) > 0 {
				t.Fatalf("got responses back when expecting an empty array")
			}
		}

		// TestServiceBase_GoodParamOneFound
		body, err, status = shared.CallNounRouterViaLoopback(router.Configuration, nil, "GUID-fake-member-GUID", "AgeOver=30")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))
			var resource shared.TestNounResource
			err = json.Unmarshal(body, &resource)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}
			if resource.TestNoun.Name != "Alice" {
				t.Errorf("handler returned unexpected name: got %v want %v", resource.TestNoun.Name, "Alice")
			}
		}

		// journal call to get entries - valid
		fakeMachineToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, false)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}
		requestURL := "v1/journal?clock=1&limit=10"
		body, err, status = shared.CallServiceViaLoopback(router.Configuration, http.MethodGet, fakeMachineToken, requestURL)
		if err != nil {
			t.Fatalf("Failed to call noun-journal router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))
			var journaled []resourceStore.ResourceJournalEntry
			err = json.Unmarshal(body, &journaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal array of journal entries response: %v", err)
			}
			if len(journaled) == 0 {
				t.Fatalf("got no journal responses back when expecting more than 1 in array")
			}
		}

		// journal call to get max clock - valid
		var maxClock resourceStore.JournalMaxClock
		requestURL = "v1/journalMaxClock"
		body, err, status = shared.CallServiceViaLoopback(router.Configuration, http.MethodGet, fakeMachineToken, requestURL)
		if err != nil {
			t.Fatalf("Failed to call noun-journal router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))

			err = json.Unmarshal(body, &maxClock)
			if err != nil {
				t.Fatalf("Failed to unmarshal max clock from noun journal: %v", err)
			}
			if maxClock.MaxClock == 0 {
				t.Fatalf("got 0 max clock when expecting a number > 0")
			}
		}

		// journal call to get the max clock entry only - valid
		requestURL = fmt.Sprintf("v1/journal?clock=%d&limit=1", maxClock.MaxClock)
		body, err, status = shared.CallServiceViaLoopback(router.Configuration, http.MethodGet, fakeMachineToken, requestURL)
		if err != nil {
			t.Fatalf("Failed to call noun-journal router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))
			var journaled []resourceStore.ResourceJournalEntry
			err = json.Unmarshal(body, &journaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal array of journal entries response: %v", err)
			}
			if len(journaled) == 0 {
				t.Fatalf("got no journal responses back when expecting 1 in array")
			}
			if len(journaled) > 1 {
				t.Fatalf("got more then one journal responses back when expecting exactly 1 in array")
			}
			if journaled[0].Clock != maxClock.MaxClock {
				t.Fatalf("got clock %d when expecting %d", journaled[0].Clock, maxClock.MaxClock)
			}
		}

		// journal call - invalid variants TODO

		// health check call
		requestURL = fmt.Sprintf("v1/health")
		body, err, status = shared.CallServiceViaLoopback(router.Configuration, http.MethodGet, nil, requestURL)
		if err != nil {
			t.Fatalf("Failed to call noun-journal router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Fatalf("Expected status %d, got %d", http.StatusOK, status)
		} else {
			fmt.Printf("Response body: %s\n", string(body))
			//			var journaled []resourceStore.ResourceJournalEntry
			var health serviceBase.HealthStatus
			err = json.Unmarshal(body, &health)
			if err != nil {
				t.Fatalf("Failed to unmarshal response: %v", err)
			}
			if health.Status != constants.HEALTH_STATUS_HEALTHY {
				t.Fatalf("got health status %s when expecting %s", health.Status, constants.HEALTH_STATUS_HEALTHY)
			}
		}

	})
}

func TestShutdownListener(t *testing.T) {
	t.Logf("Shutting down listener...")

	// Assuming the current process is the one to be shut down
	cmd := syscall.Getpid()
	process, err := os.FindProcess(cmd)
	if err != nil {
		t.Fatalf("Failed to find process: %v", err)
	}
	if err := process.Signal(syscall.SIGINT); err != nil {
		panic(err)
	}

	t.Logf("waiting 1 seconds to see shutdown")
	time.Sleep(1 * time.Second)
}
