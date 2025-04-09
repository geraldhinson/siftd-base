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

type HealthCheckRoutesHelper[R any] struct {
	*serviceBase.ServiceBase
	store *resourceStore.PostgresResourceStoreWithJournal[R]
}

func NewHealthCheckRoutesHelper[R any](serviceBase *serviceBase.ServiceBase, authModel *security.AuthModel) *HealthCheckRoutesHelper[R] {

	store, err := resourceStore.NewPostgresResourceStoreWithJournal[R](
		serviceBase.Configuration,
		serviceBase.Logger)
	if err != nil {
		serviceBase.Logger.Println("Error creating PostgresResourceStoreWithJournal:", err)
		return nil
	}

	HealthCheckRoutesHelper := &HealthCheckRoutesHelper[R]{
		ServiceBase: serviceBase,
		store:       store,
	}
	HealthCheckRoutesHelper.setupRoutes(authModel)
	if HealthCheckRoutesHelper.Router == nil {
		serviceBase.Logger.Println("Error creating HealthCheckRoutesHelper")
		return nil
	}

	return HealthCheckRoutesHelper
}

func (h *HealthCheckRoutesHelper[R]) setupRoutes(authModel *security.AuthModel) {

	var routeString = "/v1/health"
	h.RegisterRoute(constants.HTTP_GET, routeString, authModel, h.GetHealthStandalone)

}

func (h *HealthCheckRoutesHelper[R]) GetHealthStandalone(w http.ResponseWriter, r *http.Request) {
	var health = serviceBase.HealthStatus{
		Status:           constants.HEALTH_STATUS_HEALTHY,
		DependencyStatus: map[string]string{}}

	err := h.store.HealthCheck()
	if err != nil {
		h.Logger.Info("the call to the resource store HealthCheck() in GetHealthStandalone failed with: ", err)
		health.DependencyStatus["database"] = constants.HEALTH_STATUS_UNHEALTHY
		health.Status = constants.HEALTH_STATUS_UNHEALTHY
	} else {
		health.DependencyStatus["database"] = constants.HEALTH_STATUS_HEALTHY
	}

	// TODO: fix this experiment along with the method below
	h.GetListOfCalledServices(&health)

	jsonResults, errmsg := json.Marshal(health)
	if errmsg != nil {
		h.Logger.Info("Failed to convert health structure to json in GetHealthStandalone: ", errmsg)
		h.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, errmsg)
		return
	}

	h.WriteHttpOK(w, jsonResults)
}

func (h *HealthCheckRoutesHelper[R]) GetListOfCalledServices(health *serviceBase.HealthStatus) {
	// TODO: implement this method
	calledServices := h.Configuration.GetString(constants.CALLED_SERVICES)

	// Declare a slice to hold the parsed array
	//	var stringArray []string

	// Unmarshal the JSON array
	if err := json.Unmarshal([]byte(calledServices), &health.CalledServices); err != nil {
		fmt.Println("failed in GetListOfCalledServices unmarshalling called services JSON from env var:", err)
		return
	}
}
