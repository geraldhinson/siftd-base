package unitTestsShared

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/helpers"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
)

type TestNoun struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// Define struct that embeds ResourceBase
type TestNounResource struct {
	resourceStore.ResourceBase
	TestNoun TestNoun `json:"employee"`
}

type TestRouter struct {
	*serviceBase.ServiceBase
}

func (tr *TestRouter) testNounHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("GET request received with Auth token: %s\n", r.Header.Get("Authorization"))
	fmt.Printf("GET request received with URL: %s\n", r.URL.Path)

	params := mux.Vars(r)
	urlIdentity := params["identityId"]
	fmt.Printf("GET request received with identityId: %s\n", urlIdentity)

	queryParams := tr.GetQueryParams(r)
	fmt.Printf("GET request received with query params: %v\n", queryParams)
	if queryParams["AgeOver"] != "" {
		fmt.Printf("GET request received with AgeOver: %s\n", queryParams["AgeOver"])
	}

	ageOver, err := strconv.Atoi(queryParams["AgeOver"])
	if err != nil {
		tr.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("invalid AgeOver parameter: %v", err))
		return
	}

	ageOfAlice := 31

	if ageOfAlice > ageOver {
		resourceA := &TestNounResource{
			ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
			TestNoun:     TestNoun{Name: "Alice", Age: ageOfAlice},
		}
		responseBytes, err := json.Marshal(resourceA)
		if err != nil {
			tr.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
			return
		}

		tr.WriteHttpOK(w, responseBytes)
	} else {
		var emptyArray = &[]TestNounResource{}
		bytes, err := json.Marshal(emptyArray)
		if err == nil {
			tr.WriteHttpOK(w, bytes)
		} else {
			tr.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, nil)
		}
	}
}

func NewTestRouter(realm string, authType security.AuthTypes, authTimeout security.AuthTimeout, list []string) (*TestRouter, error) {
	service := serviceBase.NewServiceBase()
	if service == nil {
		return nil, fmt.Errorf("Expected non-nil serviceBase")
	} else if service.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		return nil, fmt.Errorf("Expected healthy status, got %s", service.HealthStatus.Status)
	}

	testRouter := &TestRouter{
		ServiceBase: service,
	}

	authModel, err := service.NewAuthModel(realm, authType, authTimeout, list)
	if err != nil {
		return nil, fmt.Errorf("Failed to initialize AuthModel in HealthCheckRouter : %v", err)
	}

	//	var routeString = "/v1/identities/{identityId}/employees?AgeOver={age}"
	var routeString = "/v1/identities/{identityId}/employees"
	service.RegisterRoute(constants.HTTP_GET, routeString, authModel, testRouter.testNounHandler)

	FakeIdentityServiceRouter := NewFakeIdentityServiceRouter(service)
	if FakeIdentityServiceRouter == nil {
		return nil, fmt.Errorf("Failed to create fake identity service api server (for testing only). Shutting down.")
	}

	NounJournalRouter := NewNounJournalRouter(service)
	if NounJournalRouter == nil {
		return nil, fmt.Errorf("Failed to create journal api server (for testing only). Shutting down.")
	}

	HealthCheckRouter := NewHealthCheckRouter(service)
	if HealthCheckRouter == nil {
		return nil, fmt.Errorf("Failed to create health check api server (for testing only). Shutting down.")
	}

	go service.ListenAndServe()

	return testRouter, nil

}

func CallServiceViaLoopback(configuration *viper.Viper, httpMethod string, fakeUserToken []byte, requestURLSuffix string) ([]byte, error, int) {

	listenAddress := configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		err := fmt.Errorf("Unable to retrieve listen address and port. Shutting down.")
		return nil, err, http.StatusBadRequest
	}
	requestURL := fmt.Sprintf("http://%s/%s", listenAddress, requestURLSuffix)

	req, err := http.NewRequest(httpMethod, requestURL, nil)
	if err != nil {
		err = fmt.Errorf("failed to build noun service request in UnitTest: %s", err)
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

func CallNounRouterViaLoopback(configuration *viper.Viper, fakeUserToken []byte, identity string, queryParam string) ([]byte, error, int) {
	requestURL := fmt.Sprintf("v1/identities/%s/employees?%s", identity, queryParam)
	return CallServiceViaLoopback(configuration, http.MethodGet, fakeUserToken, requestURL)
}

func CallFakeIdentityServiceViaLoopbackToGetToken(configuration *viper.Viper, userToken bool) ([]byte, error) {
	var requestURL string
	if userToken {
		requestURL = fmt.Sprintf("v1/createFakeUserToken")
	} else {
		requestURL = fmt.Sprintf("v1/createFakeMachineToken")
	}
	resbody, err, _ := CallServiceViaLoopback(configuration, http.MethodPost, nil, requestURL)

	return resbody, err
}

// this is here to enable the plumbing to call this same process back via loopback to get tokens, fetch public keys, etc.
// It is testing separately with the other helpers the service_test.go file
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

type HealthCheckRouter struct {
	*helpers.HealthCheckRoutesHelper[TestNounResource]
}

func NewHealthCheckRouter(employeeService *serviceBase.ServiceBase) *HealthCheckRouter {
	employeeService.Logger.Info("Setting up the health check router")

	// This router is mostly built using serviceBase implementation, but we don't fully implement it in
	// serviceBase because:
	// 1. We want it to be obvious that it is one of the routers this service implements (ie.
	//    easily seen in the routers folder)
	// 2. It is important for the service writer to define the auth model for all routers
	//
	authModel, err := employeeService.NewAuthModel(security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if err != nil {
		employeeService.Logger.Fatalf("Failed to initialize AuthModel in HealthCheckRouter : %v", err)
		return nil
	}

	// OK. Auth is defined. Now use the helper code to do the rest of the heavy lifting here.
	//
	HealthCheckRoutesHelper := helpers.NewHealthCheckRoutesHelper[TestNounResource](employeeService, authModel)
	if HealthCheckRoutesHelper == nil {
		employeeService.Logger.Println("Error creating HealthCheckRoutesHelper")
		return nil
	}

	HealthCheckServiceRouter := &HealthCheckRouter{
		HealthCheckRoutesHelper: HealthCheckRoutesHelper,
	}

	return HealthCheckServiceRouter
}

type NounJournalRouter struct {
	*helpers.NounJournalRoutesHelper[TestNounResource]
}

func NewNounJournalRouter(employeeService *serviceBase.ServiceBase) *NounJournalRouter {
	employeeService.Logger.Info("Setting up the noun journal router")

	// This router is mostly built using serviceBase implementation, but we don't fully implement it in
	// serviceBase because:
	// 1. We want it to be obvious that it is one of the routers this service implements (ie.
	//    easily seen in the routers folder)
	// 2. It is important for the service writer to define the auth model for all routers
	//
	authModelMachine, err := employeeService.NewAuthModel(security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil)
	if err != nil {
		employeeService.Logger.Fatalf("Failed to initialize AuthModelMachine in SecuredQueriesRouter : %v", err)
		return nil
	}

	// OK. Auth is defined. Now use the helper code to do the rest of the heavy lifting here.
	//
	NounJournalRoutesHelper := helpers.NewNounJournalRoutesHelper[TestNounResource](employeeService, authModelMachine)
	if NounJournalRoutesHelper == nil {
		employeeService.Logger.Println("Error creating NounJournalRoutesHelper")
		return nil
	}

	NounJournalServiceRouter := &NounJournalRouter{
		NounJournalRoutesHelper: NounJournalRoutesHelper,
	}

	return NounJournalServiceRouter
}
