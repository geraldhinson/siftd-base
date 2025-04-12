package unittests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/helpers"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
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

var gNounService *serviceBase.ServiceBase

func setupConfigForSecurityTest() (*viper.Viper, error) {
	// Initialize configuration
	viper.AddConfigPath(os.Getenv("RESDIR_PATH"))
	viper.SetConfigFile("app.env")
	viper.AutomaticEnv() // overrides app.env with environment variables if same name found
	err := viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("Failed to read config for service.")
	}
	configuration := viper.GetViper()

	return configuration, nil
}

func fakeNounHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("GET request received with Auth token: %s\n", r.Header.Get("Authorization"))
	fmt.Printf("GET request received with URL: %s\n", r.URL.Path)

	params := mux.Vars(r)
	urlEmployee := params["employeeId"]
	urlIdentity := params["identityId"]
	fmt.Printf("GET request received with employeeId: %s\n", urlEmployee)
	fmt.Printf("GET request received with identityId: %s\n", urlIdentity)

	resourceA := &fakeNounResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		FakeNoun:     fakeNoun{Name: "Alice", Age: 30},
	}
	responseBytes, err := json.Marshal(resourceA)
	if err != nil {
		http.Error(w, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write(responseBytes)
}

func Test_InvalidAuthModels(t *testing.T) {
	gNounService = serviceBase.NewServiceBase()
	if gNounService == nil {
		t.Fatalf("Expected non-nil serviceBase")
	} else if gNounService.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		t.Fatalf("Expected healthy status, got %s", gNounService.HealthStatus.Status)
	}

	// invalid combos of NO_* with anything else
	_, err := gNounService.NewAuthModel(security.NO_REALM, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = gNounService.NewAuthModel(security.REALM_INTERNAL, security.NO_AUTH, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MACHINE, security.VALID_IDENTITY, security.NO_EXPIRY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}
	_, err = gNounService.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, []string{"Joe Bob"})
	if err == nil {
		t.Fatalf("Failed to prevent mixing the NO_* with the other types of security params/lists")
	}

	// ensure that we cannot add a NO_* after valid policy for a given realm and vice versa
	authModel, err := gNounService.NewAuthModel(security.REALM_CSRC, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent adding a the NO_* policy for a realm when a previous policy was already added")
	}
	authModel, err = gNounService.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.REALM_CSRC, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err == nil {
		t.Fatalf("Failed to prevent adding a the NO_* policy for a realm when a previous policy was already added")
	}

	// ensure that the APPROVED_* polices have a list and that lists are not provided for the non-APPROVED_* policies
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_DAY, nil) // no list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_GROUPS without also providing a list of groups")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_DAY, []string{}) // empty list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_GROUPS when the groups list is empty")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_DAY, nil) // no list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_IDENTITIES without also providing a list of identities")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_DAY, []string{}) // missing list
	if err == nil {
		t.Fatalf("Failed to prevent specifying APPROVED_IDENTITIES when the groups list is empty")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_DAY, []string{"1234"}) // list sans APPROVED_*
	if err == nil {
		t.Fatalf("Failed to prevent providing list when not using APPROVED_* policies")
	}
	_, err = gNounService.NewAuthModel(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_DAY, []string{}) // empty list sans APPROVED_*
	if err == nil {
		t.Fatalf("Failed to prevent providing list when not using APPROVED_* policies")
	}

	// ensure that we cannot add mutliple policies for the same realm with different expiries
	authModel, err = gNounService.NewAuthModel(security.REALM_CSRC, security.MATCHING_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to create a valid auth model to use for a follow on test: %v", err)
	}
	err = authModel.AddPolicy(security.REALM_CSRC, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"Joe Bob"})
	if err == nil {
		t.Fatalf("Failed to prevent adding multiple policies for the same realm with different expiries")
	}

}

func TestNounHandler_NoAuth(t *testing.T) {
	srv, err := setupRoutes(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, nil, "GUID-fake-member-GUID")
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.VALID_IDENTITY, security.ONE_DAY, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {

		expiredToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY3M2IxOWEwLWZhZjktNGJmNS04MWUyLTE4NjY5Zjg1MTNjNiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3NDQyNDk3MTMsImlzcyI6InNpZnRkLXNlcnZpY2UtYmFzZSIsImp0aSI6ImI4MTZiMjA3LWZlMjYtNDVkNi04YTlhLWZmNWU1Y2M0NWI5NiIsInJvbGVzIjpbImFkbWluIl0sInN1YiI6IkdVSUQtZmFrZS1tZW1iZXItR1VJRCIsInN1Yl9uYW1lIjoiRmFrZSAoTWVtYmVyKSBVc2VyIiwic3ViX3R5cGUiOiJNZW1iZXIifQ.Y0okgVgWujtc7PNpILKqTeUh-yvAi5QGkHpmalmVPTFzBK5fId0FRGxnbBDZ2Ds0U8VkusStVOsyCw0xkGeDYhxUKo8p7V_Sg2pxa1YS31a9xPHPxNrdEHNOk5ZvTciwicGvVAMmb2XUnliz49RKDm9T0skmW8I35vRyA03hxARyRl5a6xqezWHYj1OQbdKHf3ftYIWbGvjbNKdF0FcwGcX-nvmfUaFtOwIjQUe-_YVHRFI06vKNYf-cHqhIWHFl-TNFKQbtyTlxHVVwJ3IGxCOoAA_boU6rJLjfcxcmDVzAKxm0c0JatTky3kcTOeDj_wnQV8umrtxMQ5jvJkpPGQ"
		expiredTokenBytes := []byte(expiredToken)

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, expiredTokenBytes, "GUID-fake-member-GUID")
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.VALID_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "GUID-fake-member-GUID")
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "diffent-identy-from-token") // NOT the same as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "GUID-fake-member-GUID") // same as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"GUID-fake-member-GUID"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "different-identity") // not as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_HOUR, []string{"Joe Bob"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "Joe Bob") // NOT the same as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_HOUR, []string{"admin"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "different-identity") // not as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_HOUR, []string{"operations"}) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, true)
		if err != nil {
			t.Fatalf("failed to get fake user token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "Joe Bob") // NOT the same as on token from fake identity service
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
	srv, err := setupRoutes(security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil) // as on token from fake identity service
	if err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer srv.Shutdown(context.Background())

	t.Run("GET request", func(t *testing.T) {
		var isUserIdentity = false
		fakeUserToken, err := CallFakeIdentityServiceViaLoopbackToGetToken(gNounService.Configuration, isUserIdentity)
		if err != nil {
			t.Fatalf("failed to get fake machine realm token: %s", err)
		}

		body, err, status := CallNounRouterViaLoopback(gNounService.Configuration, fakeUserToken, "different-identity") // not as on token from fake identity service
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

func CallNounRouterViaLoopback(configuration *viper.Viper, fakeUserToken []byte, identity string) ([]byte, error, int) {

	listenAddress := configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		err := fmt.Errorf("Unable to retrieve listen address and port. Shutting down.")
		return nil, err, http.StatusBadRequest
	}

	requestURL := fmt.Sprintf("http://%s/v1/identities/%s/employees/fake-EMPLOYEE-GUID-fake", listenAddress, identity)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		err = fmt.Errorf("failed to build noun service request in KeyCache: %s", err)
		return nil, err, http.StatusBadRequest
	}
	if (fakeUserToken != nil) && (len(fakeUserToken) > 0) {
		req.Header.Add("Authorization", string(fakeUserToken))
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("client call to noun service failed with : %s", err)
		return nil, err, http.StatusBadRequest
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("unable to read noun service reply: %s", err)
		return nil, err, http.StatusBadRequest
	}

	return resBody, err, res.StatusCode
}

func CallFakeIdentityServiceViaLoopbackToGetToken(configuration *viper.Viper, userToken bool) ([]byte, error) {

	listenAddress := configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		err := fmt.Errorf("Unable to retrieve listen address and port. Shutting down.")
		return nil, err
	}

	var requestURL string
	if userToken {
		requestURL = fmt.Sprintf("http://%s/v1/createFakeUserToken", listenAddress)
	} else {
		requestURL = fmt.Sprintf("http://%s/v1/createFakeMachineToken", listenAddress)
	}
	req, err := http.NewRequest(http.MethodPost, requestURL, nil)
	if err != nil {
		err = fmt.Errorf("failed to build identity service request in KeyCache: %s", err)
		return nil, err
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("client call to identity service failed with : %s", err)
		return nil, err
	}

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("unable to read identity service reply: %s", err)
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("identity service returned status code: %d", res.StatusCode)
		return nil, err
	}

	// resBody is the public key, return it
	return resBody, nil
}

func Listener(router *mux.Router) (*http.Server, error) {
	configuration, err := setupConfigForSecurityTest()
	if configuration == nil {
		return nil, fmt.Errorf("Failed to setup configuration for test %v", err)
	}

	//	setupRoutes(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)

	// setup
	listenAddress := configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		return nil, fmt.Errorf("Unable to retrieve listen address and port. Shutting down.")
	}

	fmt.Printf("This service is listening on: %s", listenAddress)

	srv := &http.Server{
		Addr:    listenAddress,
		Handler: router,
	}
	go srv.ListenAndServe()

	// pause until the server is up // TODO: make this less timing and more definitive (which will be faster too)
	time.Sleep(2 * time.Second)

	return srv, nil
}

func setupRoutes(realm string, authType security.AuthTypes, authTimeout security.AuthTimeout, list []string) (*http.Server, error) {
	gNounService = serviceBase.NewServiceBase()
	if gNounService == nil {
		return nil, fmt.Errorf("Expected non-nil serviceBase")
	} else if gNounService.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		return nil, fmt.Errorf("Expected healthy status, got %s", gNounService.HealthStatus.Status)
	}

	authModel, err := gNounService.NewAuthModel(realm, authType, authTimeout, list)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize AuthModel in HealthCheckRouter : %v", err)
	}

	var routeString = "/v1/identities/{identityId}/employees/{employeeId}"
	gNounService.RegisterRoute(constants.HTTP_GET, routeString, authModel, fakeNounHandler)

	FakeIdentityServiceRouter := NewFakeIdentityServiceRouter(gNounService)
	if FakeIdentityServiceRouter == nil {
		return nil, fmt.Errorf("Failed to create fake identity service api server (for testing only). Shutting down.")
	}

	srv, err := Listener(gNounService.Router)
	if err != nil {
		return nil, fmt.Errorf("Failed to start listener: %v", err)
	}
	time.Sleep(2 * time.Second)

	return srv, nil
}

type FakeIdentityServiceRouter struct {
	*helpers.FakeIdentityServiceRoutesHelper
}

func NewFakeIdentityServiceRouter(employeeService *serviceBase.ServiceBase) *FakeIdentityServiceRouter {
	employeeService.Logger.Info("Setting up the fake identity service router")

	// This router is mostly built using serviceBase implementation, but we don't fully implement it in
	// serviceBase because:
	// 1. We want it to be obvious that it is one of the routers this service implements (ie.
	//    easily seen in the routers folder)
	// 2. It is important for the service writer to define the auth model for all routers
	//
	authModel, err := employeeService.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		employeeService.Logger.Fatalf("Failed to initialize AuthModel in FakeIdentityServiceRouter : %v", err)
		return nil
	}

	// OK. Auth is defined. Now use the helper code to do the rest of the heavy lifting here.
	//
	FakeIdentityServiceRoutesHelper := helpers.NewFakeIdentityServiceRoutesHelper(employeeService, authModel)
	if FakeIdentityServiceRoutesHelper == nil {
		employeeService.Logger.Println("Error creating FakeIdentityServiceRoutesHelper")
		return nil
	}

	FakeIdentityServiceRouter := &FakeIdentityServiceRouter{
		FakeIdentityServiceRoutesHelper: FakeIdentityServiceRoutesHelper,
	}

	return FakeIdentityServiceRouter
}
