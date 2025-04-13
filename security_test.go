package unittests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	shared "github.com/geraldhinson/siftd-base/pkg/unitTestsShared"
	"github.com/gorilla/mux"
)

type fakeNoun struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// Define struct that embeds ResourceBase
type fakeNounResource struct {
	resourceStore.ResourceBase
	FakeNoun fakeNoun `json:"employee"`
}

type UnitTestRouter struct {
	*serviceBase.ServiceBase
	httpServer *http.Server
}

func (ur *UnitTestRouter) testNounHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	urlIdentity := params["identityId"]
	fmt.Printf("GET request received with identityId: %s\n", urlIdentity)

	queryParams := ur.GetQueryParams(r)
	fmt.Printf("GET request received with query params: %v\n", queryParams)

	// ignoring query params in this test

	resourceA := &fakeNounResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		FakeNoun:     fakeNoun{Name: "Alice", Age: 100},
	}
	responseBytes, err := json.Marshal(resourceA)
	if err != nil {
		ur.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	ur.WriteHttpOK(w, responseBytes)
}

func Test_InvalidAuthModels(t *testing.T) {
	service := serviceBase.NewServiceBase()
	if service == nil {
		t.Fatalf("Expected non-nil serviceBase")
	} else if service.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		t.Fatalf("Expected healthy status, got %s", service.HealthStatus.Status)
	}

	// invalid combos of NO_* with anything else
	_, err := service.NewAuthModel(security.NO_REALM, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = service.NewAuthModel(security.REALM_INTERNAL, security.NO_AUTH, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = service.NewAuthModel(security.REALM_MACHINE, security.VALID_IDENTITY, security.NO_EXPIRY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = service.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, []string{"Joe Bob"})
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}

	// ensure that we cannot add a NO_* after valid policy for a given realm and vice versa
	authModel, err := service.NewAuthModel(security.REALM_CSRC, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent adding a the NO_* policy for a realm when a previous policy was already added")
	}
	authModel, err = service.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.REALM_CSRC, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent adding a the NO_* policy for a realm when a previous policy was already added")
	}

	// ensure that the APPROVED_* polices have a list and that lists are not provided for the non-APPROVED_* policies
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_DAY, nil) // no list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_GROUPS without also providing a list of groups")
	}
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_DAY, []string{}) // empty list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_GROUPS when the groups list is empty")
	}
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_DAY, nil) // no list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_IDENTITIES without also providing a list of identities")
	}
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_DAY, []string{}) // missing list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_IDENTITIES when the groups list is empty")
	}
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_DAY, []string{"1234"}) // list sans APPROVED_*
	if err == nil {
		t.Fatalf("Failed to prevent providing list when not using APPROVED_* policies")
	}
	_, err = service.NewAuthModel(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_DAY, []string{}) // empty list sans APPROVED_*
	if err == nil {
		t.Fatalf("Failed to prevent providing list when not using APPROVED_* policies")
	}

	// ensure that we cannot add mutliple policies for the same realm with different expiries
	authModel, err = service.NewAuthModel(security.REALM_CSRC, security.MATCHING_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.REALM_CSRC, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"Joe Bob"})
	if err == nil {
		t.Fatalf("Failed to prevent adding multiple policies for the same realm with different expiries")
	}

}

func TestNounHandler_NoAuth(t *testing.T) {
	router, err := NewUnitTestRouter(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, nil, "GUID-fake-member-GUID", "AgeOver=10")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		fmt.Printf("Response body: %s\n", string(body))
		var resource fakeNounResource
		err = json.Unmarshal(body, &resource)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}
		if resource.FakeNoun.Name != "Alice" {
			t.Errorf("handler returned unexpected name: got %v want %v", resource.FakeNoun.Name, "Alice")
		}
	})
}

func TestNounHandler_RealmValidIdentity_ExpiredToken(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {

		expiredToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2IxOWEwLWZhZjktNGJmNS04MWUyLTE4NjY5Zjg1MTNjNiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NDQyNDk3MTMsImlzcyI6InNpZnRkLXNlcnZpY2UtYmFzZSIsImp0aSI6ImI4MTZiMjA3LWZlMjYtNDVkNi04YTlhLWZmNWU1Y2M0NWI5NiIsInJvbGVzIjpbImFkbWluIl0sInN1YiI6IkdVSUQtZmFrZS1tZW1iZXItR1VJRCIsInN1Yl9uYW1lIjoiRmFrZSAoTWVtYmVyKSBVc2VyIiwic3ViX3R5cGUiOiJNZW1iZXIifQ.Y0okgVgWujtc7PNpILKqTeUh-yvAi5QGkHpmalmVPTFzBK5fId0FRGxnbBDZ2Ds0U8VkusStVOsyCw0xkGeDYhxUKo8p7V_Sg2pxa1YS31a9xPHPxNrdEHNOk5ZvTciwicGvVAMmb2XUnliz49RKDm9T0skmW8I35vRyA03hxARyRl5a6xqezWHYj1OQbdKHf3ftYIWbGvjbNKdF0FcwGcX-nvmfUaFtOwIjQUe-_YVHRFI06vKNYf-cHqhIWHFl-TNFKQbtyTlxHVVwJ3IGxCOoAA_boU6rJLjfcxcmDVzAKxm0c0JatTky3kcTOeDj_wnQV8umrtxMQ5jvJkpPGQ"
		expiredTokenBytes := []byte(expiredToken)

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, expiredTokenBytes, "GUID-fake-member-GUID", "AgeOver=10")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusUnauthorized {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
		}
		if string(body) != "" {
			t.Errorf("handler returned unexpected non-nil body: %s", string(body))
		}
	})

}

func TestNounHandler_RealmValidIdentity_ValidToken(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.VALID_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "GUID-fake-member-GUID", "AgeOver=10")
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		fmt.Printf("Response body: %s\n", string(body))
		var resource fakeNounResource
		err = json.Unmarshal(body, &resource)
		if err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}
		if resource.FakeNoun.Name != "Alice" {
			t.Errorf("handler returned unexpected name: got %v want %v", resource.FakeNoun.Name, "Alice")
		}

	})
}

func TestNounHandler_RealmMatchingIdentity_InvalidToken(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "diffent-identy-from-token", "AgeOver=10") // NOT the same as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
		}
		if string(body) != "" {
			t.Errorf("handler returned unexpected non-nil body: %s", string(body))
		}
	})

}

func TestNounHandler_RealmMatchingIdentity_ValidToken(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "GUID-fake-member-GUID", "AgeOver=10") // same as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
		if string(body) == "" {
			t.Errorf("handler returned unexpected nil body: %s", string(body))
		}
		fmt.Printf("Response body: %s\n", string(body))
	})

}

func TestNounHandler_RealmApprovedIdentities_InList(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"GUID-fake-member-GUID"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "different-identity", "AgeOver=10") // not as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
		if string(body) == "" {
			t.Errorf("handler returned unexpected nil body: %s", string(body))
		}
		fmt.Printf("Response body: %s\n", string(body))
	})
}

func TestNounHandler_RealmApprovedIdentities_NotInList(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"Joe Bob"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "Joe Bob", "AgeOver=10") // NOT the same as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
		}
		if string(body) != "" {
			t.Errorf("handler returned unexpected non-nil body: %s", string(body))
		}
	})
}

func TestNounHandler_RealmApprovedGroups_IsGroupMember(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_HOUR, []string{"admin"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "different-identity", "AgeOver=10") // not as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
		if string(body) == "" {
			t.Errorf("handler returned unexpected nil body: %s", string(body))
		}
		fmt.Printf("Response body: %s\n", string(body))
	})
}

func TestNounHandler_RealmApprovedGroups_IsNotGroupMember(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_HOUR, []string{"operations"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "Joe Bob", "AgeOver=10") // NOT the same as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusForbidden {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusForbidden)
		}
		if string(body) != "" {
			t.Errorf("handler returned unexpected non-nil body: %s", string(body))
		}
	})
}

func TestNounHandler_RealmMachine_ValidIdentity(t *testing.T) {
	router, err := NewUnitTestRouter(security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer router.httpServer.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		var isUserIdentity = false
		fakeUserToken, err := shared.CallFakeIdentityServiceViaLoopbackToGetToken(router.Configuration, isUserIdentity)
		if err != nil {
			t.Fatalf("failed to get fake machine realm token: %s", err)
		}

		body, err, status := shared.CallNounRouterViaLoopback(router.Configuration, fakeUserToken, "different-identity", "AgeOver=10") // not as on token from fake identity service
		if err != nil {
			t.Fatalf("Failed to call noun router via loopback: %v, %d", err, status)
		}
		if status != http.StatusOK {
			t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
		}
		if string(body) == "" {
			t.Errorf("handler returned unexpected nil body: %s", string(body))
		}
		fmt.Printf("Response body: %s\n", string(body))
	})
}

//-----
//----- Test support Functions below here
//-----

func Listener(service *serviceBase.ServiceBase) (*http.Server, error) {

	// setup
	listenAddress := service.Configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		return nil, fmt.Errorf("Unable to retrieve listen address and port. Shutting down.")
	}

	fmt.Printf("This service is listening on: %s\n", listenAddress)

	srv := &http.Server{
		Addr:    listenAddress,
		Handler: service.Router,
	}
	go srv.ListenAndServe()

	// pause until the server is up // TODO: make this less timing and more definitive (which will be faster too)
	PauseUntilListening(listenAddress)
	//	time.Sleep(2 * time.Second)

	return srv, nil
}

func PauseUntilListening(listenAddress string) {
	// Wait for the server to start listening
	for {
		conn, err := net.Dial("tcp", listenAddress)
		if err == nil {
			conn.Close()
			break
		}
		fmt.Println("Waiting for server to start...")
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("Server is now listening.")
}

func NewUnitTestRouter(realm string, authType security.AuthTypes, authTimeout security.AuthTimeout, list []string) (*UnitTestRouter, error) {
	service := serviceBase.NewServiceBase()
	if service == nil {
		return nil, fmt.Errorf("Expected non-nil serviceBase")
	} else if service.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		return nil, fmt.Errorf("Expected healthy status, got %s", service.HealthStatus.Status)
	}

	unitTestRouter := &UnitTestRouter{
		ServiceBase: service,
		httpServer:  nil,
	}

	authModel, err := unitTestRouter.NewAuthModel(realm, authType, authTimeout, list)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize AuthModel in HealthCheckRouter : %v", err)
	}

	var routeString = "/v1/identities/{identityId}/employees"
	unitTestRouter.RegisterRoute(constants.HTTP_GET, routeString, authModel, unitTestRouter.testNounHandler)

	FakeIdentityServiceRouter := shared.NewFakeIdentityServiceRouter(service)
	if FakeIdentityServiceRouter == nil {
		return nil, fmt.Errorf("Failed to create fake identity service api server (for testing only). Shutting down.")
	}

	unitTestRouter.httpServer, err = Listener(service)
	if err != nil {
		return nil, fmt.Errorf("Failed to start listener: %v", err)
	}

	return unitTestRouter, nil

}
