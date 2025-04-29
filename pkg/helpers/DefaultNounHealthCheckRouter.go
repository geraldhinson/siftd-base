package helpers

// It is not required to use this helper implementation, but it is provided as a convenience
// since the code is likely to be identical for each noun service.
//

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
)

type HealthCheckRouter[R any] struct {
	*serviceBase.ServiceBase
	store *resourceStore.PostgresResourceStoreWithJournal[R]
}

func NewNounHealthCheckRouter[R any](
	serviceBase *serviceBase.ServiceBase,
	realm string,
	authType security.AuthTypes,
	timeout security.AuthTimeout,
	approvedList []string) *HealthCheckRouter[R] {

	authModel, err := serviceBase.NewAuthModel(realm, authType, timeout, approvedList)
	if err != nil {
		serviceBase.Logger.Info("noun healthcheck router - failed to initialize AuthModel with ", err)
		return nil
	}

	store, err := resourceStore.NewPostgresResourceStoreWithJournal[R](
		serviceBase.Configuration,
		serviceBase.Logger)
	if err != nil {
		serviceBase.Logger.Info("noun healthcheck router - error creating PostgresResourceStoreWithJournal with ", err)
		return nil
	}

	healthCheckRouter := &HealthCheckRouter[R]{
		ServiceBase: serviceBase,
		store:       store,
	}

	healthCheckRouter.setupRoutes(authModel)
	if healthCheckRouter.Router == nil {
		serviceBase.Logger.Info("noun healthcheck router - error creating NounHealthCheck router")
		return nil
	}

	return healthCheckRouter
}

func (h *HealthCheckRouter[R]) setupRoutes(authModel *security.AuthModel) {

	var routeString = "/v1/health"
	h.RegisterRoute(constants.HTTP_GET, routeString, authModel, h.GetHealthStandalone)

}

func (h *HealthCheckRouter[R]) GetHealthStandalone(w http.ResponseWriter, r *http.Request) {
	var health = serviceBase.HealthStatus{
		Status:           constants.HEALTH_STATUS_HEALTHY,
		DependencyStatus: map[string]string{}}

	err := h.store.HealthCheck()
	if err != nil {
		h.Logger.Info("noun healthcheck router - the call to the resource store HealthCheck() in GetHealthStandalone failed with: ", err)
		health.DependencyStatus["database"] = constants.HEALTH_STATUS_UNHEALTHY
		health.Status = constants.HEALTH_STATUS_UNHEALTHY
	} else {
		health.DependencyStatus["database"] = constants.HEALTH_STATUS_HEALTHY
	}

	err = h.GetListOfCalledServices(&health)
	if err != nil {
		h.Logger.Info("noun healthcheck router - failed to retrieve called services in GetHealthStandalone: ", err)
		health.CalledServices = []string{err.Error()}
		health.Status = constants.HEALTH_STATUS_UNHEALTHY
	}

	jsonResults, errmsg := json.Marshal(health)
	if errmsg != nil {
		h.Logger.Info("noun healthcheck router - failed to convert health structure to json in GetHealthStandalone: ", errmsg)
		h.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, errmsg)
		return
	}

	h.WriteHttpOK(w, jsonResults)
}

func (h *HealthCheckRouter[R]) GetListOfCalledServices(health *serviceBase.HealthStatus) error {
	// TODO: implement this method
	calledServices := h.Configuration.GetString(constants.CALLED_SERVICES)
	if calledServices == "" {
		return fmt.Errorf("noun healthcheck router - called services not defined in env var: %s", constants.CALLED_SERVICES)
	}

	// Unmarshal the JSON array
	if err := json.Unmarshal([]byte(calledServices), &health.CalledServices); err != nil {
		return fmt.Errorf("noun healthcheck router - unmarshalling of called services JSON from env var failed with %w", err)
	}

	return nil
}
