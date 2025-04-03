package helpers

// It is not required to use this helper implementation, but it is provided as a convenience
// since the code is likely to be identical for each noun service.
//

import (
	"net/http"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	"github.com/gorilla/mux"
)

type FakeIdentityServiceRoutesHelper struct {
	*serviceBase.ServiceBase
	FakeKeyStore *security.KeyStore
}

func NewFakeIdentityServiceRoutesHelper(serviceBase *serviceBase.ServiceBase, authModel *security.AuthModel) *FakeIdentityServiceRoutesHelper {

	fakeKeyStore := security.NewFakeKeyStore(serviceBase.Configuration, serviceBase.Logger)
	if fakeKeyStore == nil {
		serviceBase.Logger.Println("Error creating FakeKeyStore")
		return nil
	}

	FakeIdentityServiceHelper := &FakeIdentityServiceRoutesHelper{
		ServiceBase:  serviceBase,
		FakeKeyStore: fakeKeyStore,
	}

	FakeIdentityServiceHelper.setupRoutes(authModel)
	if FakeIdentityServiceHelper.Router == nil {
		serviceBase.Logger.Println("Error creating FakeIdentityServiceHelper")
		return nil
	}

	return FakeIdentityServiceHelper
}

func (k *FakeIdentityServiceRoutesHelper) setupRoutes(authModel *security.AuthModel) {
	var routeString = "/v1/createFakeUserToken"
	k.RegisterRoute(constants.HTTP_POST, routeString, authModel, k.handleFakeUserLogin)

	routeString = "/v1/createFakeMachineToken"
	k.RegisterRoute(constants.HTTP_POST, routeString, authModel, k.handleFakeServiceLogin)

	routeString = "/v1/keys/{keyId}"
	k.RegisterRoute(constants.HTTP_GET, routeString, authModel, k.handleFakeGetPublicKey)

}

func (k *FakeIdentityServiceRoutesHelper) handleFakeUserLogin(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("Incoming request to create a fake user login token (for testing): %s", r.URL.Path)

	token, err := k.FakeKeyStore.JwtFakeUserLogin()
	if err != nil {
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	k.WriteHttpOK(w, token)
}

func (k *FakeIdentityServiceRoutesHelper) handleFakeServiceLogin(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("Incoming request to create a fake machine token (for testing): %s", r.URL.Path)

	token, err := k.FakeKeyStore.JwtFakeServiceLogin()
	if err != nil {
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	k.WriteHttpOK(w, token)
}

func (k *FakeIdentityServiceRoutesHelper) handleFakeGetPublicKey(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("Incoming request to get a public key by id(for testing): %s", r.URL.Path)
	params := mux.Vars(r)
	kid := params["keyId"]

	publicKeyBytes, err := k.FakeKeyStore.GetPublicKey(kid)
	if err != nil {
		k.Logger.Infof("failed to fetch public key from identity service: %v", err)
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
	} else {
		k.WriteHttpOK(w, publicKeyBytes)
	}
}
