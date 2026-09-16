package helpers

// It is not required to use this helper implementation, but it is provided as a convenience
// since the code is likely to be identical for each noun service.
//
import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
)

type NounJournalRouter[R any] struct {
	*serviceBase.ServiceBase
	store    *resourceStore.PostgresResourceStoreWithJournal[R]
	maxLimit int32
}

func NewNounJournalRouter[R any](
	serviceBase *serviceBase.ServiceBase,
	realm string,
	authType security.AuthTypes,
	timeout security.AuthTimeout,
	approvedList []string) *NounJournalRouter[R] {

	maxLimit, err := DetermineMaxLimitForRequests(serviceBase)
	if err != nil {
		serviceBase.Logger.Info("noun journal router - failed to determine max limit for journal requests ", err)
		return nil
	}

	authModel, err := serviceBase.NewAuthModel(realm, authType, timeout, approvedList)
	if err != nil {
		serviceBase.Logger.Info("noun journal router - failed to initialize AuthModel with ", err)
		return nil
	}

	store, err := resourceStore.NewPostgresJournaledResourceStore[R](
		serviceBase.Configuration,
		serviceBase.Logger,
		constants.JOURNAL_DB_POOL_MAX_CONNS,
	)
	if err != nil {
		serviceBase.Logger.Info("noun journal router - error creating PostgresResourceStoreWithJournal with ", err)
		return nil
	}

	nounJournalRouter := &NounJournalRouter[R]{
		ServiceBase: serviceBase,
		store:       store,
		maxLimit:    maxLimit,
	}

	nounJournalRouter.setupRoutes(authModel)
	if nounJournalRouter.Router == nil {
		store.Close()

		serviceBase.Logger.Info("noun journal router - error creating NounJournalRouter")
		return nil
	}

	if err := serviceBase.RegisterShutdown(store.Close); err != nil {
		store.Close()

		serviceBase.Logger.Infof(
			"noun journal router - failed to register store shutdown: %v",
			err,
		)

		return nil
	}
	return nounJournalRouter
}

func DetermineMaxLimitForRequests(serviceBase *serviceBase.ServiceBase) (int32, error) {
	const defaultMaxLimit int32 = 1000

	maxLimit := defaultMaxLimit

	configuredValue := strings.TrimSpace(
		serviceBase.Configuration.GetString(constants.JOURNAL_MAX_BATCH_SIZE),
	)

	if configuredValue != "" {
		parsedValue, err := strconv.ParseInt(
			configuredValue,
			10,
			32,
		)
		if err != nil {
			return -1, fmt.Errorf(
				"noun journal router - invalid integer value %q for %s: %w",
				configuredValue,
				constants.JOURNAL_MAX_BATCH_SIZE,
				err,
			)
		}

		if parsedValue < 1 {
			return -1, fmt.Errorf(
				"noun journal router - %s must be greater than zero",
				constants.JOURNAL_MAX_BATCH_SIZE,
			)
		}

		maxLimit = int32(parsedValue)
	}

	if configuredValue == "" {
		serviceBase.Logger.Infof(
			"noun journal reader - journal request limit configured with default maximum batch size of %d",
			maxLimit,
		)
	} else {
		serviceBase.Logger.Infof(
			"noun journal reader - journal request limit configured with a maximum batch size of %d using %s",
			maxLimit,
			constants.JOURNAL_MAX_BATCH_SIZE,
		)
	}

	return maxLimit, nil
}

func (j *NounJournalRouter[R]) setupRoutes(authModel *security.AuthModel) {
	var routeString = "/v1/journal"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalChanges)

	routeString = "/v1/journalMaxClock"
	j.RegisterRoute(constants.HTTP_GET, routeString, authModel, j.GetJournalMaxClock)

}

func (j *NounJournalRouter[R]) GetJournalChanges(w http.ResponseWriter, r *http.Request) {

	params := j.GetQueryParams(r)
	clock, err := strconv.ParseInt(params["clock"], 10, 64)
	if err != nil {
		j.Logger.Info("noun journal router - failed to parse 'clock' parameter in GetJournalChanges: ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	if clock < 1 {
		err := errors.New("invalid < 1 'clock' parameter in GetJournalChanges")
		j.Logger.Info("noun journal router - ", err)
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
		err := errors.New("invalid < 1 'limit' parameter in GetJournalChanges")
		j.Logger.Info("noun journal router - ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}
	if limit > int64(j.maxLimit) {
		err := fmt.Errorf(
			"invalid 'limit' parameter exceeds the configured maximum of %d",
			j.maxLimit,
		)

		j.Logger.Info("noun journal router - ", err)
		j.WriteHttpError(w, constants.RESOURCE_BAD_REQUEST_CODE, err)
		return
	}

	var journalEntries []resourceStore.ResourceJournalEntry
	status, err := j.store.GetJournalChanges(clock, limit, &journalEntries)
	//	START HERE with GetJournalChanges returning error code like the other methods do the noun router
	if err != nil {
		if status == constants.RESOURCE_INTERNAL_ERROR_CODE {
			j.Logger.Error("noun journal router - call to resource store GetJournalChanges() in GetJournalChanges failed with: ", err)
		} else {
			j.Logger.Info("noun journal router - call to resource store GetJournalChanges() in GetJournalChanges failed with: ", err)
		}

		j.WriteHttpError(w, status, err)
		return
	}

	jsonResults, errmsg := json.Marshal(journalEntries)
	if errmsg != nil {
		j.Logger.Error("noun journal router - call to json marshall journal entries in GetJournalChanges failed with : ", errmsg)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR))
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
		j.Logger.Error("noun journal router - call to resource store get the journal's max clock in GetJournalMaxClock failed with: ", err)
		j.WriteHttpError(w, constants.RESOURCE_INTERNAL_ERROR_CODE, err)
		return
	}

	var jsonResults = []byte(fmt.Sprintf("{\"maxClock\": %d}", maxClock))

	j.WriteHttpOK(w, jsonResults)
}
