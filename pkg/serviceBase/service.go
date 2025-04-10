package serviceBase

import (
	"fmt"
	"net/http"
	"os"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type HealthStatus struct {
	Status           string            `json:"status"`
	DependencyStatus map[string]string `json:"dependencyStatus"`
	CalledServices   []string          `json:"calledServices"`
}

type ServiceBase struct {
	Configuration *viper.Viper
	Logger        *logrus.Logger
	Router        *mux.Router
	KeyCache      *security.KeyCache
	HealthStatus  *HealthStatus
}

// ValidateConfigAndListen configures the services for the Queries Service and listens for incoming requests
func NewServiceBase() *ServiceBase {

	logger, configuration := setup()
	if logger == nil || configuration == nil {
		fmt.Println("Setup failed for service. Shutting down.")
		return nil
	}

	serviceInstanceName := configuration.GetString(constants.SERVICE_INSTANCE_NAME)
	if serviceInstanceName == "" {
		logger.Info("Service instance name is not set in the configuration. Shutting down.")
		return nil
	}
	logger.Infof("Validating configuration for [Service: %s]", serviceInstanceName)

	keyCache := security.NewPublicKeyCache(configuration, logger)
	if keyCache == nil {
		logger.Info("Failed to create key store. Shutting down.")
		return nil
	}

	router := mux.NewRouter()

	health := &HealthStatus{
		Status:           constants.HEALTH_STATUS_HEALTHY,
		DependencyStatus: map[string]string{},
		CalledServices:   []string{},
	}

	return &ServiceBase{
		Configuration: configuration,
		Logger:        logger,
		Router:        router,
		KeyCache:      keyCache,
		HealthStatus:  health,
	}
}

func setup() (*logrus.Logger, *viper.Viper) {
	// Initialize logger
	logger := logrus.New()
	if logger == nil {
		fmt.Println("Failed to create logger for service. Shutting down.")
		return nil, nil
	}

	// Initialize configuration
	viper.AddConfigPath(os.Getenv("RESDIR_PATH"))
	viper.SetConfigFile("app.env")
	viper.AutomaticEnv() // overrides app.env with environment variables if same name found
	err := viper.ReadInConfig()
	if err != nil {
		logger.Info("Failed to read config for service. Shutting down.")
		return nil, nil
	}
	configuration := viper.GetViper()

	return logger, configuration
}

// convenience function to simplify the call to the actual NewAuthModel (in Auth.go)
//
// Example usage from a service:
//
//   authModel, err := NewAuthModel(security.REALM_MEMBER, security.MATCHING_IDENTITY, security.ONE_DAY, nil)
//
// To add additional policies to the authModel, use the AddPolicy method (note that the AddPolicy calls are done on the returned authModel):
//
//   err = authModel.AddPolicy(security.REALM_MEMBER, security.APPROVED_GROUPS, security.ONE_DAY, []string{"admin"})
//   err = authModel.AddPolicy(security.REALM_MEMBER, security.APPROVED_IDENTITIES, security.ONE_DAY, []string{"GUID-fake-member-GUID"})
//   err = authModel.AddPolicy(security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil)
//
// You can also call NewAuthModel multiple times if you want to create differing auth models for different routes.
// For example you mght want to secure routes that are only available to admins or members of a given realm.
//
//   authModel, err := NewAuthModel(security.REALM_MACHINE, security.VALID_IDENTITY, security.ONE_HOUR, nil)
//

func (sb *ServiceBase) NewAuthModel(realm string, authType security.AuthTypes, authTimeout security.AuthTimeout, list []string) (*security.AuthModel, error) {

	authModel := security.NewAuthModel(sb.Configuration, sb.Logger, sb.KeyCache)

	err := authModel.AddPolicy(realm, authType, authTimeout, list)
	if err != nil {
		sb.Logger.Errorf("Failed to create auth policy: %v", err)
		return nil, err
	}

	//	sb.Logger.Infof("Auth model created with policies: %v", policies)
	return authModel, err
}

func (sb *ServiceBase) RegisterRoute(httpMethod string, routeString string, authModelUsers *security.AuthModel, handler func(http.ResponseWriter, *http.Request)) {
	sb.Router.HandleFunc(routeString, authModelUsers.Secure(handler)).Methods(httpMethod)
	sb.Logger.Infof("Registered route: %s %s", httpMethod, routeString)
}

func (sb *ServiceBase) WriteHttpError(w http.ResponseWriter, status int, v error) {
	var httpStatus int = http.StatusInternalServerError

	switch status {
	case constants.RESOURCE_NOT_FOUND_ERROR_CODE:
		httpStatus = http.StatusNotFound
	case constants.RESOURCE_BAD_REQUEST_CODE:
		httpStatus = http.StatusBadRequest
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	w.Write([]byte(v.Error()))
}

func (sb *ServiceBase) WriteHttpOK(w http.ResponseWriter, v []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(v)
}

func (sb *ServiceBase) GetQueryParams(r *http.Request) map[string]string {
	queryParams := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			queryParams[key] = values[0]
		}
	}
	return queryParams
}
