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

type FakeIdentityServiceRouter struct {
	*serviceBase.ServiceBase
	FakeKeyStore *security.KeyStore
}

func NewFakeIdentityServiceRouter(
	serviceBase *serviceBase.ServiceBase,
	realm string,
	authType security.AuthTypes,
	timeout security.AuthTimeout,
	approvedList []string) *FakeIdentityServiceRouter {

	fakeKeyStore := security.NewFakeKeyStore(serviceBase.Configuration, serviceBase.Logger)
	if fakeKeyStore == nil {
		serviceBase.Logger.Info("fake identity service router - error creating FakeKeyStore")
		return nil
	}

	authModel, err := serviceBase.NewAuthModel(realm, authType, timeout, approvedList)
	if err != nil {
		serviceBase.Logger.Info("fake identity service router - failed to initialize AuthModel with ", err)
		return nil
	}

	fakeIdentityServiceRouter := &FakeIdentityServiceRouter{
		ServiceBase:  serviceBase,
		FakeKeyStore: fakeKeyStore,
	}

	fakeIdentityServiceRouter.setupRoutes(authModel)
	if fakeIdentityServiceRouter.Router == nil {
		serviceBase.Logger.Info("fake identity service router - error creating FakeIdentityService router")
		return nil
	}

	return fakeIdentityServiceRouter
}

func (k *FakeIdentityServiceRouter) setupRoutes(authModel *security.AuthModel) {
	var routeString = "/v1/createFakeUserToken"
	k.RegisterRoute(constants.HTTP_POST, routeString, authModel, k.handleFakeUserLogin)

	routeString = "/v1/createFakeMachineToken"
	k.RegisterRoute(constants.HTTP_POST, routeString, authModel, k.handleFakeServiceLogin)

	routeString = "/v1/keys/{keyId}"
	k.RegisterRoute(constants.HTTP_GET, routeString, authModel, k.handleFakeGetPublicKey)

}

func (k *FakeIdentityServiceRouter) handleFakeUserLogin(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("fake identity service router - incoming request to create a fake user login token (for testing): %s", r.URL.Path)

	token, err := k.FakeKeyStore.JwtFakeUserLogin()
	if err != nil {
		k.Logger.Infof("fake identity service router - failed to create fake user token: %v", err)
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	k.Logger.Infof("fake identity service router - successfully created fake user token")
	k.WriteHttpOK(w, token)
}

func (k *FakeIdentityServiceRouter) handleFakeServiceLogin(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("fake identity service router - incoming request to create a fake machine token (for testing): %s", r.URL.Path)

	token, err := k.FakeKeyStore.JwtFakeServiceLogin()
	if err != nil {
		k.Logger.Infof("fake identity service router - failed to create fake machine token: %v", err)
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	k.Logger.Infof("fake identity service router - successfully created fake machine token")
	k.WriteHttpOK(w, token)
}

func (k *FakeIdentityServiceRouter) handleFakeGetPublicKey(w http.ResponseWriter, r *http.Request) {
	k.Logger.Infof("fake identity service router - incoming request to get a public key by id(for testing): %s", r.URL.Path)
	params := mux.Vars(r)
	kid := params["keyId"]

	publicKeyBytes, err := k.FakeKeyStore.GetPublicKey(kid)
	if err != nil {
		k.Logger.Infof("fake identity service router - failed to find public key in fake identity service: %v", err)
		k.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
	} else {
		k.Logger.Infof("fake identity service router - successfully found public key in fake identity service")
		k.WriteHttpOK(w, publicKeyBytes)
	}
}
