package serviceBase

import (
	"fmt"
	"net/http"
	"os"

	"github.com/geraldhinson/siftd/service-base/pkg/constants"
	"github.com/geraldhinson/siftd/service-base/pkg/security"
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
		fmt.Println("Setup failed for query service. Shutting down.")
		return nil
	}

	logger.Infof("Validating configuration for [Service: %s]", configuration.GetString(constants.SERVICE_INSTANCE_NAME))

	keyCache := security.NewPublicKeyCache(configuration, logger)
	if keyCache == nil {
		logger.Fatalf("Failed to create key store. Shutting down.")
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
		fmt.Println("Failed to create logger for query service. Shutting down.")
		return nil, nil
	}

	// Initialize configuration
	viper.AddConfigPath(os.Getenv("RESDIR_PATH"))
	viper.SetConfigFile("app.env")
	viper.AutomaticEnv() // overrides app.env with environment variables if same name found
	err := viper.ReadInConfig()
	if err != nil {
		logger.Info("Failed to read config for query service. Shutting down.")
		return nil, nil
	}
	configuration := viper.GetViper()

	return logger, configuration
}

// convenience function to simplify the call to NewAuthModel
func (sb *ServiceBase) NewAuthModel(authTimeout security.AuthTimeout, authTypes []security.AuthTypes, authGroups []security.AuthGroups) *security.AuthModel {
	return security.NewAuthModelExpanded(sb.Configuration, sb.Logger, sb.KeyCache, authTimeout, authTypes, authGroups)
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
