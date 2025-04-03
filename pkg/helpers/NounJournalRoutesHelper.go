package helpers

// It is not required to use this helper implementation, but it is provided as a convenience
// since the code is likely to be identical for each noun service.
//
import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/geraldhinson/siftd/service-base/pkg/constants"
	"github.com/geraldhinson/siftd/service-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd/service-base/pkg/security"
	"github.com/geraldhinson/siftd/service-base/pkg/serviceBase"
)

type NounJournalRoutesHelper[R any] struct {
	*serviceBase.ServiceBase
	store *resourceStore.PostgresResourceStoreWithJournal[R]
}

func NewNounJournalRoutesHelper[R any](serviceBase *serviceBase.ServiceBase, authModel *security.AuthModel, store *resourceStore.PostgresResourceStoreWithJournal[R]) *NounJournalRoutesHelper[R] {

	nounJournalRoutesHelper := &NounJournalRoutesHelper[R]{
		ServiceBase: serviceBase,
		store:       store,
	}
	nounJournalRoutesHelper.setupRoutes(authModel)
	if nounJournalRoutesHelper.Router == nil {
		serviceBase.Logger.Println("Error creating NounJournalRoutesHelper")
		return nil
	}

	return nounJournalRoutesHelper
}

func (j *NounJournalRoutesHelper[R]) setupRoutes(authModel *security.AuthModel) {
	var routeString = "/v1/journal"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalChanges)

	routeString = "/v1/journalMaxClock"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalMaxClock)

}

func (j *NounJournalRoutesHelper[R]) GetJournalChanges(w http.ResponseWriter, r *http.Request) {

	params := j.GetQueryParams(r)
	clock, err := strconv.ParseInt(params["clock"], 10, 64)
	if err != nil {
		j.Logger.Info("Failed to parse 'clock' parameter: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	limit, err := strconv.ParseInt(params["limit"], 10, 64)
	if err != nil {
		j.Logger.Info("Failed to parse 'clock' parameter: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	var journalEntries []resourceStore.ResourceJournalEntry
	err = j.store.GetJournalChanges(clock, limit, &journalEntries)
	//	START HERE with GetJournalChanges returning error code like the other methods do the noun router
	if err != nil {
		j.Logger.Info("Call to GetJournalChanges in GetJournalChanges failed with: ", err)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
		return
	}

	jsonResults, errmsg := json.Marshal(journalEntries)
	if errmsg != nil {
		j.Logger.Info("Call to json marshall journal entries in GetJournalChanges failed with : ", errmsg)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, errmsg)
		return
	}
	// make empty array if no results found - it's friendlier to the client
	if string(jsonResults) == "null" {
		jsonResults = []byte("[]")
	}

	j.WriteHttpOK(w, jsonResults)
}

func (j *NounJournalRoutesHelper[R]) GetJournalMaxClock(w http.ResponseWriter, r *http.Request) {
	var maxClock uint64
	err := j.store.GetJournalMaxClock(&maxClock)
	//	START HERE with GetJournalChanges returning error code like the other methods do the noun router
	if err != nil {
		j.Logger.Info("Call to GetJournalMaxClock in GetJournalMaxClock failed with: ", err)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
		return
	}

	var jsonResults = []byte(fmt.Sprintf("{\"maxClock\": %d}", maxClock))

	j.WriteHttpOK(w, jsonResults)
}
