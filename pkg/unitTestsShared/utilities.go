package unitTestsShared

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

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

	FakeIdentityServiceRouter := helpers.NewFakeIdentityServiceRouter(service, security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
	if FakeIdentityServiceRouter == nil {
		return nil, fmt.Errorf("Failed to create fake identity service api server (for testing only). Shutting down.")
	}

	NounJournalRouter := helpers.NewNounJournalRouter[TestNounResource](service, security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil)
	if NounJournalRouter == nil {
		return nil, fmt.Errorf("Failed to create journal api server (for testing only). Shutting down.")
	}

	HealthCheckRouter := helpers.NewNounHealthCheckRouter[TestNounResource](service, security.NO_REALM, security.NO_AUTH, security.NO_EXPIRY, nil)
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
	requestURL := fmt.Sprintf("%s/%s", listenAddress, requestURLSuffix)

	req, err := http.NewRequest(httpMethod, requestURL, nil)
	if err != nil {
		err = fmt.Errorf("failed to build noun service request in UnitTest: %s", err)
		return nil, err, http.StatusBadRequest
	}
	if (fakeUserToken != nil) && (len(fakeUserToken) > 0) {
		req.Header.Add("Authorization", string(fakeUserToken))
	}

	var res *http.Response
	if strings.Contains(listenAddress, "https") && strings.Contains(requestURL, "localhost") {
		// all of this is required if this service is acting as a fake identity service and listening on
		// localhost with a self-signed cert. We have to setup the client call to trust the self-signed cert
		// just like we have to do for postman or a browser.
		path := configuration.GetString("RESDIR_PATH")
		if path == "" {
			err = fmt.Errorf("unable to retrieve RESDIR_PATH - shutting down")
			return nil, err, http.StatusBadRequest
		}
		httpsListenCert := configuration.GetString(constants.HTTPS_CERT_FILENAME)
		if httpsListenCert == "" {
			err = fmt.Errorf("unable to retrieve HTTPS certificate file - shutting down")
			return nil, err, http.StatusBadRequest
		}

		caCert, err := os.ReadFile(path + "/" + httpsListenCert)
		if err != nil {
			return nil, err, http.StatusBadRequest
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    caCertPool,
					ServerName: "localhost", // must match SAN
					//				InsecureSkipVerify: true,
				},
			},
		}
		res, err = client.Do(req)
	} else {
		// this is the normal case where we are calling the identity service
		// and it is not localhost and we are not using a self-signed cert
		res, err = http.DefaultClient.Do(req)
	}

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
