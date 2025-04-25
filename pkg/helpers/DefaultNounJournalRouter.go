package helpers

// It is not required to use this helper implementation, but it is provided as a convenience
// since the code is likely to be identical for each noun service.
//
import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
)

type NounJournalRouter[R any] struct {
	*serviceBase.ServiceBase
	store *resourceStore.PostgresResourceStoreWithJournal[R]
}

func NewNounJournalRouter[R any](
	serviceBase *serviceBase.ServiceBase,
	realm string,
	authType security.AuthTypes,
	timeout security.AuthTimeout,
	approvedList []string) *NounJournalRouter[R] {

	authModel, err := serviceBase.NewAuthModel(realm, authType, timeout, approvedList)
	if err != nil {
		serviceBase.Logger.Info("noun journal router - failed to initialize AuthModel with ", err)
		return nil
	}

	store, err := resourceStore.NewPostgresResourceStoreWithJournal[R](
		serviceBase.Configuration,
		serviceBase.Logger)
	if err != nil {
		serviceBase.Logger.Info("noun journal router - error creating PostgresResourceStoreWithJournal with ", err)
		return nil
	}

	nounJournalRouter := &NounJournalRouter[R]{
		ServiceBase: serviceBase,
		store:       store,
	}

	nounJournalRouter.setupRoutes(authModel)
	if nounJournalRouter.Router == nil {
		serviceBase.Logger.Info("noun journal router - error creating NounJournalRouter")
		return nil
	}

	return nounJournalRouter
}

func (j *NounJournalRouter[R]) setupRoutes(authModel *security.AuthModel) {
	var routeString = "/v1/journal"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalChanges)

	routeString = "/v1/journalMaxClock"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalMaxClock)

}

func (j *NounJournalRouter[R]) GetJournalChanges(w http.ResponseWriter, r *http.Request) {

	// TODO: do some validity checks on the clock and limit values passed (e.g. clock > 0, limit > 0)

	params := j.GetQueryParams(r)
	clock, err := strconv.ParseInt(params["clock"], 10, 64)
	if err != nil {
		j.Logger.Info("noun journal router - failed to parse 'clock' parameter in GetJournalChanges: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	if clock < 1 {
		j.Logger.Info("noun journal router - invalid 'clock' parameter in GetJournalChanges: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	limit, err := strconv.ParseInt(params["limit"], 10, 64)
	if err != nil {
		j.Logger.Info("noun journal router - failed to parse 'limit' parameter in GetJournalChanges: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	if limit < 1 {
		j.Logger.Info("noun journal router - invalid 'limit' parameter in GetJournalChanges: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	var journalEntries []resourceStore.ResourceJournalEntry
	err = j.store.GetJournalChanges(clock, limit, &journalEntries)
	//	START HERE with GetJournalChanges returning error code like the other methods do the noun router
	if err != nil {
		j.Logger.Info("noun journal router - call to resource store GetJournalChanges() in GetJournalChanges failed with: ", err)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
		return
	}

	jsonResults, errmsg := json.Marshal(journalEntries)
	if errmsg != nil {
		j.Logger.Info("noun journal router - call to json marshall journal entries in GetJournalChanges failed with : ", errmsg)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, errmsg)
		return
	}
	// make empty array if no results found - it's friendlier to the client
	if string(jsonResults) == "null" {
		jsonResults = []byte("[]")
	}

	j.WriteHttpOK(w, jsonResults)
}

func (j *NounJournalRouter[R]) GetJournalMaxClock(w http.ResponseWriter, r *http.Request) {
	var maxClock uint64
	err := j.store.GetJournalMaxClock(&maxClock)
	//	START HERE with GetJournalChanges returning error code like the other methods do the noun router
	if err != nil {
		j.Logger.Info("noun journal router - call to resource store get the journal's max clock in GetJournalMaxClock failed with: ", err)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
		return
	}

	var jsonResults = []byte(fmt.Sprintf("{\"maxClock\": %d}", maxClock))

	j.WriteHttpOK(w, jsonResults)
}
