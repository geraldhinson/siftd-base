package resourceStore

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/security"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// PostgresResourceStoreWithJournal is the Go equivalent of the C# PostgresResourceStoreWithJournal class
type PostgresResourceStoreWithJournal[R any] struct {
	dbConnectString      string
	journalPartitionName string
	logger               *logrus.Logger
	dbPool               *pgxpool.Pool
	rootCtx              *context.Context
	cancel               *context.CancelFunc //TODO: not using this currently
	Cmds                 *PostgresCommandHelper
	// resource        R
}

// private methods below here
func NewPostgresResourceStoreWithJournal[R any](configuration *viper.Viper, logger *logrus.Logger) (*PostgresResourceStoreWithJournal[R], error) {
	// validate that R is a struct that included an embedded ResourceBase struct
	testR := new(R)
	if _, ok := any(testR).(IResource); !ok {
		return nil, fmt.Errorf("the type R is not a valid resource type. It is missing an embedded ResourceBase struct")
	}

	// validate inputs
	if configuration == nil {
		return nil, fmt.Errorf("configuration is nil")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is nil")
	}

	store := &PostgresResourceStoreWithJournal[R]{logger: logger, Cmds: &PostgresCommandHelper{}}

	store.dbConnectString = configuration.GetString(constants.DB_CONNECTION_STRING)
	if store.dbConnectString == "" {
		return nil, fmt.Errorf("unable to retrieve database connection string")
	}

	store.journalPartitionName = configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if store.journalPartitionName == "" {
		return nil, fmt.Errorf("unable to retrieve journal partition name")
	}

	// Initialize the database pool (example with pgx)
	connConfig, err := pgxpool.ParseConfig(store.dbConnectString)
	if err != nil {
		return nil, fmt.Errorf("unable to parse connection config: %v", err)
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	store.rootCtx = &rootCtx
	store.cancel = &cancel
	//	defer cancel()

	store.dbPool, err = pgxpool.NewWithConfig(*store.rootCtx, connConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %v", err)
	}
	//	defer store.dbPool.Close()

	// Verify the connection
	err = store.dbPool.Ping(*store.rootCtx)
	if err != nil {
		return nil, fmt.Errorf("unable to ping database: %w", err)
	}
	logger.Info("Successfully connected to database")

	return store, nil
}

// HealthCheck performs a health check on the database
func (store *PostgresResourceStoreWithJournal[R]) HealthCheck() error {

	query := store.Cmds.GetHealthCheckCommand()

	rows, err := store.dbPool.Query(*store.rootCtx, query)
	// rows, err := store.dbPool.Query(*store.rootCtx, query, ids)
	if err != nil {
		store.logger.Error("Error detected on HealthCheck query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()
	return nil
}

// GetById retrieves a resource by its ID
func (store *PostgresResourceStoreWithJournal[R]) GetById(id string, ownerId string, resource *R) (int, error) {
	// validate that R is a struct that includes the ResourceBase struct

	query, params := store.Cmds.GetResourceByIdCommand(id, ownerId)

	rows, err := store.dbPool.Query(*store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("Error detected on GetById query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	if rows.Next() {
		var resourceData []byte
		if err := rows.Scan(&resourceData); err != nil {
			return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("db error scanning result in GetById: %w", err)
		}

		err := json.Unmarshal(resourceData, resource)
		if err != nil {
			return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("error unmarshaling JSON in GetById: %w", err)
		}

		//		if resource.Deleted && throwExceptions {
		//			return nil, fmt.Errorf("Resource not found (deleted): %v", id)
		//		}
	} else {
		return constants.RESOURCE_NOT_FOUND_ERROR_CODE, fmt.Errorf("resource not found: %v", id)
	}

	return constants.RESOURCE_OK_CODE, nil // resource found - no error
}

// GetByOwner retrieves resources by owner ID
func (store *PostgresResourceStoreWithJournal[R]) GetByOwnerId(ownerId string, resources *[]R) (int, error) {
	query, params := store.Cmds.GetResourcesByOwnerIdCommand(ownerId)

	rows, err := store.dbPool.Query(*store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("Error detected on GetByOwnerId query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	for rows.Next() {
		var resourceData []byte
		var resource R
		if err := rows.Scan(&resourceData); err != nil {
			return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("error scanning result in GetByOwnerId: %w", err)
		}
		err := json.Unmarshal(resourceData, &resource)
		if err != nil {
			return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("error unmarshaling JSON in GetByOwnerId: %w", err)
		}
		*resources = append(*resources, resource)
	}

	//TODO: should I do this or just allow it to return below and let the caller respond
	// with an empty array and http200
	//	if len(*resources) == 0 {
	//		return constants.RESOURCE_NOT_FOUND_ERROR_CODE, fmt.Errorf("no resources found for owner: %v", ownerId)
	//	}

	return constants.RESOURCE_OK_CODE, nil
}

// GetJournalChanges retrieves changes >= clock up to limit entries
// We support >= clock to allow for fetching a specific clock entry (e.g. clock = 25, limit = 1) when the client
// has the clock value for that one and needs to fetch it again for some reason.
func (store *PostgresResourceStoreWithJournal[R]) GetJournalChanges(clock int64, limit int64, journalEntries *[]ResourceJournalEntry) error {
	query, params := store.Cmds.GetJournalChangesCommand(clock, limit)

	rows, err := store.dbPool.Query(*store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("Error detected on GetJournalChanges query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	for rows.Next() {
		var journalEntry ResourceJournalEntry
		if err := rows.Scan(&journalEntry.Clock, &journalEntry.Resource, &journalEntry.UpdatedAt, &journalEntry.PartitionName); err != nil {
			return fmt.Errorf("error scanning result in GetJournalChanges: %w", err)
		}
		*journalEntries = append(*journalEntries, journalEntry)
	}

	return nil
}

func (store *PostgresResourceStoreWithJournal[R]) GetJournalMaxClock(maxClock *uint64) error {
	query := store.Cmds.GetJournalMaxClockCommand()

	rows, err := store.dbPool.Query(*store.rootCtx, query)
	if err != nil {
		store.logger.Error("Error detected on GetJournalMaxClock query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(maxClock)
		if err != nil {
			store.logger.Info("Null result detected on scan of journal clock. This is expected if no journal entries exist.")
			*maxClock = 0
			return nil
		}
	}

	return nil
}

// CreateResource creates a new resource
func (store *PostgresResourceStoreWithJournal[R]) CreateResource(resource IResource, extractedAuth string) (IResource, int, error) {
	identities := security.ValidateAuthToken(extractedAuth)
	if len(identities) == 0 {
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("no identities found in auth token")
	}

	now := time.Now().UTC()
	resourceBase := resource.GetResourceBase()
	resourceBase.CreatedAt = now
	resourceBase.UpdatedAt = resourceBase.CreatedAt
	resourceBase.Version = 1
	resourceBase.Deleted = false

	// generate unique ID if not provided (but allow for it to be provided)
	if resourceBase.Id == "" {
		resourceBase.Id = uuid.New().String()
	}

	resourceBase.UpdatedBy = identities["sub"]
	resourceBase.ImpersonatedBy = identities["impersonatedBy"]

	jsonResource, err := json.Marshal(resource)
	if err != nil {
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("error serializing resource in CreateResource: %w", err)
	}

	query, params := store.Cmds.GetInsertResourceWithJournalCommand(resource, jsonResource, store.journalPartitionName)

	_, err = store.dbPool.Exec(*store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("Error detected on db insert in CreateResource: ", err)

		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == constants.PRIMARY_KEY_VIOLATION_SQL_CODE {
			return nil, constants.RESOURCE_ALREADY_EXISTS_CODE, fmt.Errorf("resource save failed for: %v", resourceBase.Id)
		}
		// We don't pass unantcipated database errors back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	return resource, constants.RESOURCE_OK_CODE, nil
}

// CreateResource creates a new resource
func (store *PostgresResourceStoreWithJournal[R]) UpdateResource(resource IResource, ownerId string, resourceId string, extractedAuth string) (IResource, int, error) {
	identities := security.ValidateAuthToken(extractedAuth)
	if len(identities) == 0 {
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("no identities found in auth token")
	}

	// validate that the resource id in the URL matches the resource id in the body and
	// that the owner id in the URL matches the owner id in the body
	resourceBase := resource.GetResourceBase()
	if resourceBase.OwnerId != ownerId {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("owner id passed in the request does not match owner id in body")
	}
	if resourceBase.Id != resourceId {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("resource id passed in the request does not match resource id in body")
	}

	resourceBase.UpdatedBy = identities["sub"]
	resourceBase.ImpersonatedBy = identities["impersonatedBy"]

	now := time.Now().UTC()
	resourceBase.UpdatedAt = now
	versionToUpdate := resourceBase.Version
	resourceBase.Version++

	jsonResource, err := json.Marshal(resource)
	if err != nil {
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf("error serializing resource in UpdateResource: %w", err)
	}

	query, params := store.Cmds.GetUpdateResourceWithJournalCommand(resource, versionToUpdate, jsonResource, store.journalPartitionName)

	command, err := store.dbPool.Exec(*store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("Error detected on db update in UpdateResource: ", err)

		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == constants.PRIMARY_KEY_VIOLATION_SQL_CODE {
			return nil, constants.RESOURCE_ALREADY_EXISTS_CODE, fmt.Errorf("resource update failed: %v", resourceBase.Id)
		}

		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	if command.RowsAffected() == 0 {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("no rows were updated because the resource id does not exist or the If-Match was not correct")
	}

	return resource, constants.RESOURCE_OK_CODE, nil
}
