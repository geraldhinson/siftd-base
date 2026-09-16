package resourceStore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
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
	rootCtx              context.Context
	cancel               context.CancelFunc
	closeOnce            sync.Once
	Cmds                 *PostgresCommandHelper
	// resource        R
}

// Deprecated: use NewPostgresJournaledResourceStore to configure
// the connection-pool size.
func NewPostgresResourceStoreWithJournal[R any](configuration *viper.Viper, logger *logrus.Logger) (*PostgresResourceStoreWithJournal[R], error) {
	return NewPostgresJournaledResourceStore[R](
		configuration,
		logger,
		"",
	)
}

// private methods below here
func NewPostgresJournaledResourceStore[R any](configuration *viper.Viper, logger *logrus.Logger, maxConnsConfigKey string) (*PostgresResourceStoreWithJournal[R], error) {
	// validate that R is a struct that included an embedded ResourceBase struct
	testR := new(R)
	if _, ok := any(testR).(IResource); !ok {
		return nil, fmt.Errorf("resource store - the type R is not a valid resource type. It is missing an embedded ResourceBase struct")
	}

	// validate inputs
	if configuration == nil {
		return nil, fmt.Errorf("resource store - invalid nil configuration detected")
	}
	if logger == nil {
		return nil, fmt.Errorf("resource store - invalid nil logger detected")
	}

	store := &PostgresResourceStoreWithJournal[R]{logger: logger, Cmds: &PostgresCommandHelper{}}

	store.dbConnectString = configuration.GetString(constants.DB_CONNECTION_STRING)
	if store.dbConnectString == "" {
		return nil, fmt.Errorf("resource store - unable to retrieve database connection string")
	}

	store.journalPartitionName = configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if store.journalPartitionName == "" {
		return nil, fmt.Errorf("resource store - unable to retrieve journal partition name")
	}

	maxConnections, err := store.DetermineMaxConnectionPoolSize(configuration, logger, maxConnsConfigKey)
	if err != nil {
		return nil, err
	}

	// Initialize the database pool (example with pgx)
	connConfig, err := pgxpool.ParseConfig(store.dbConnectString)
	if err != nil {
		return nil, fmt.Errorf("resource store - unable to parse connection config: %v", err)
	}
	store.rootCtx, store.cancel = context.WithCancel(context.Background())

	connConfig.MaxConnIdleTime = 60 * time.Second
	connConfig.MaxConnLifetime = 60 * time.Second
	connConfig.MaxConns = maxConnections
	//	defer cancel()

	store.dbPool, err = pgxpool.NewWithConfig(store.rootCtx, connConfig)
	if err != nil {
		store.cancel()

		return nil, fmt.Errorf("resource store - unable to connect to database: %v", err)
	}

	// Verify the connection
	err = store.dbPool.Ping(store.rootCtx)
	if err != nil {
		store.dbPool.Close()
		store.cancel()

		return nil, fmt.Errorf("resource store - unable to ping database to verify successful connection: %w", err)
	}
	logger.Info("resource store - successfully connected to database")

	return store, nil
}

func (store *PostgresResourceStoreWithJournal[R]) Close() {
	if store == nil {
		return
	}

	store.closeOnce.Do(func() {
		if store.cancel != nil {
			store.cancel()
		}

		if store.dbPool != nil {
			store.dbPool.Close()
		}
	})
}

func (store *PostgresResourceStoreWithJournal[R]) DetermineMaxConnectionPoolSize(configuration *viper.Viper, logger *logrus.Logger, maxConnsConfigKey string) (int32, error) {
	const defaultDBPoolMaxConns int32 = 15

	maxConns := defaultDBPoolMaxConns

	if maxConnsConfigKey != "" {
		configuredValue := strings.TrimSpace(
			configuration.GetString(maxConnsConfigKey),
		)

		if configuredValue != "" {
			parsedValue, err := strconv.ParseInt(
				configuredValue,
				10,
				32,
			)
			if err != nil {
				return -1, fmt.Errorf(
					"resource store - invalid integer value %q for %s: %w",
					configuredValue,
					maxConnsConfigKey,
					err,
				)
			}

			if parsedValue < 1 {
				return -1, fmt.Errorf(
					"resource store - %s must be greater than zero",
					maxConnsConfigKey,
				)
			}

			maxConns = int32(parsedValue)
		}
	}

	if maxConnsConfigKey == "" {
		logger.Infof(
			"resource store - database pool configured with default maximum of %d connections",
			maxConns,
		)
	} else {
		logger.Infof(
			"resource store - database pool configured with maximum of %d connections using %s",
			maxConns,
			maxConnsConfigKey,
		)
	}

	return maxConns, nil
}

// GetById retrieves a resource by its ID
func (store *PostgresResourceStoreWithJournal[R]) GetById(ownerId string, id string, resource *R) (int, error) {
	// validate that R is a struct that includes the ResourceBase struct

	query, params := store.Cmds.GetResourceByIdCommand(id, ownerId)

	rows, err := store.dbPool.Query(store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("resource store - error detected on GetById query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			store.logger.Error("resource store - error fetching results in GetById: ", err)

			return constants.RESOURCE_INTERNAL_ERROR_CODE,
				fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
		}

		return constants.RESOURCE_NOT_FOUND_ERROR_CODE,
			fmt.Errorf("resource store - resource not found: %v", id)
	}

	var resourceData []byte
	if err := rows.Scan(&resourceData); err != nil {
		store.logger.Error(
			"resource store - db error scanning result in GetById: ",
			err,
		)
		return constants.RESOURCE_INTERNAL_ERROR_CODE,
			fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	err = json.Unmarshal(resourceData, resource)
	if err != nil {
		store.logger.Error(
			"resource store - error unmarshaling JSON in GetById: ",
			err,
		)
		return constants.RESOURCE_INTERNAL_ERROR_CODE,
			fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	return constants.RESOURCE_OK_CODE, nil // resource found - no error
}

// GetByOwner retrieves resources by owner ID
func (store *PostgresResourceStoreWithJournal[R]) GetByOwnerId(ownerId string, resources *[]R) (int, error) {
	query, params := store.Cmds.GetResourcesByOwnerIdCommand(ownerId)

	rows, err := store.dbPool.Query(store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("resource store - error detected on GetByOwnerId query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return constants.RESOURCE_INTERNAL_ERROR_CODE,
			fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	for rows.Next() {
		var resourceData []byte
		var resource R
		if err := rows.Scan(&resourceData); err != nil {
			store.logger.Error("resource store - error scanning result in GetByOwnerId: ", err)

			return constants.RESOURCE_INTERNAL_ERROR_CODE,
				fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
		}
		err := json.Unmarshal(resourceData, &resource)
		if err != nil {
			store.logger.Error("resource store - error unmarshaling JSON in GetByOwnerId: ", err)

			return constants.RESOURCE_INTERNAL_ERROR_CODE,
				fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
		}
		*resources = append(*resources, resource)
	}

	if err := rows.Err(); err != nil {
		store.logger.Error("resource store - error iterating results in GetByOwnerId: ", err)

		return constants.RESOURCE_INTERNAL_ERROR_CODE,
			fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
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
func (store *PostgresResourceStoreWithJournal[R]) GetJournalChanges(
	clock int64,
	limit int64,
	journalEntries *[]ResourceJournalEntry,
) (int, error) {

	// basic valildity checks - stronger checks than these can be in the caller as appropriate
	// (as is done in the default journal router)
	if clock < 1 {
		return constants.RESOURCE_BAD_REQUEST_CODE,
			fmt.Errorf("resource store - error detected on GetJournalChange query: clock must be greater than zero")
	}

	if limit < 1 {
		return constants.RESOURCE_BAD_REQUEST_CODE,
			fmt.Errorf("resource store - error detected on GetJournalChange query: limit must be greater than zero")
	}

	query, params := store.Cmds.GetJournalChangesCommand(clock, limit)

	rows, err := store.dbPool.Query(store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("resource store - error detected on GetJournalChanges query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()

	for rows.Next() {
		var journalEntry ResourceJournalEntry
		if err := rows.Scan(
			&journalEntry.Clock,
			&journalEntry.Resource,
			&journalEntry.UpdatedAt,
			&journalEntry.PartitionName,
		); err != nil {
			store.logger.Error("resource store - error scanning result in GetJournalChanges: ", err)

			return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
		}
		*journalEntries = append(*journalEntries, journalEntry)
	}

	if err := rows.Err(); err != nil {
		store.logger.Error(
			"resource store - error iterating results in GetJournalChanges: ",
			err,
		)

		return constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	return constants.RESOURCE_OK_CODE, nil
}

func (store *PostgresResourceStoreWithJournal[R]) GetJournalMaxClock(maxClock *uint64) error {
	query := store.Cmds.GetJournalMaxClockCommand()

	err := store.dbPool.QueryRow(store.rootCtx, query).Scan(maxClock)
	if err != nil {
		store.logger.Error("resource store - error detected on GetJournalMaxClock query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	return nil
}

// CreateResource creates a new resource
func (store *PostgresResourceStoreWithJournal[R]) CreateResource(resource IResource, extractedAuth string) (IResource, int, error) {
	identities := security.ValidateAuthToken(extractedAuth)
	if len(identities) == 0 {
		store.logger.Error("resource store - no identities found in auth token in CreateResource")

		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
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
		store.logger.Error("resource store - error serializing resource in CreateResource: ", err)

		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	query, params := store.Cmds.GetInsertResourceWithJournalCommand(resource, jsonResource, store.journalPartitionName)

	_, err = store.dbPool.Exec(store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("resource store - error detected on db insert in CreateResource: ", err)

		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == constants.PRIMARY_KEY_VIOLATION_SQL_CODE {
			return nil, constants.RESOURCE_ALREADY_EXISTS_CODE, fmt.Errorf("resource store - resource save failed for %v in CreateResource due to duplicate key", resourceBase.Id)
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
		store.logger.Error("resource store - no identities found in auth token in UpdateResource")

		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	// validate that the resource id in the URL matches the resource id in the body and
	// that the owner id in the URL matches the owner id in the body
	resourceBase := resource.GetResourceBase()
	if resourceBase.OwnerId != ownerId {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("resource store - owner id passed in the request does not match owner id in body in UpdateResource")
	}
	if resourceBase.Id != resourceId {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("resource store - resource id passed in the request does not match resource id in body in UpdateResource")
	}

	// make a copy of resourceBase to restore if the update below fails
	originalResourceBase := *resourceBase
	updateSucceeded := false

	defer func() {
		if !updateSucceeded {
			*resourceBase = originalResourceBase
		}
	}()

	// update fields
	resourceBase.UpdatedBy = identities["sub"]
	resourceBase.ImpersonatedBy = identities["impersonatedBy"]

	now := time.Now().UTC()
	resourceBase.UpdatedAt = now
	versionToUpdate := resourceBase.Version
	resourceBase.Version++

	jsonResource, err := json.Marshal(resource)
	if err != nil {
		store.logger.Error("resource store - error serializing resource in UpdateResource: ", err)

		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}

	query, params := store.Cmds.GetUpdateResourceWithJournalCommand(resource, versionToUpdate, jsonResource, store.journalPartitionName)

	command, err := store.dbPool.Exec(store.rootCtx, query, params)
	if err != nil {
		store.logger.Error("resource store - error detected on db update in UpdateResource: ", err)

		if pgErr, ok := err.(*pgconn.PgError); ok && pgErr.Code == constants.PRIMARY_KEY_VIOLATION_SQL_CODE {
			return nil, constants.RESOURCE_ALREADY_EXISTS_CODE, fmt.Errorf("resource store - resource update failed for %v in UpdateResource", resourceBase.Id)
		}

		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return nil, constants.RESOURCE_INTERNAL_ERROR_CODE, fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	if command.RowsAffected() == 0 {
		return nil, constants.RESOURCE_BAD_REQUEST_CODE, fmt.Errorf("resource store - no rows were updated because the resource id does not exist or the If-Match was not correct in UpdateResource")
	}

	updateSucceeded = true

	return resource, constants.RESOURCE_OK_CODE, nil
}

// HealthCheck performs a health check on the database
func (store *PostgresResourceStoreWithJournal[R]) HealthCheck() error {
	store.MonitorPoolStats()

	query := store.Cmds.GetHealthCheckCommand()

	rows, err := store.dbPool.Query(store.rootCtx, query)
	// rows, err := store.dbPool.Query(store.rootCtx, query, ids)
	if err != nil {
		store.logger.Error("resource store - error detected on HealthCheck query: ", err)
		// We don't pass the database error back to the caller. We log it and return a generic error message.
		// This is to prevent leaking sensitive information to the caller.
		return fmt.Errorf(constants.INTERNAL_SERVER_ERROR)
	}
	defer rows.Close()
	return nil
}

func (store *PostgresResourceStoreWithJournal[R]) MonitorPoolStats() {
	stats := store.dbPool.Stat()
	statsMap := make(map[string]int)

	statsMap["total_connections"] = int(stats.TotalConns())
	statsMap["acquired_connections"] = int(stats.AcquiredConns())
	statsMap["idle_connections"] = int(stats.IdleConns())
	statsMap["max_connections"] = int(stats.MaxConns())
	statsMap["max_connection_lifetime"] = int(store.dbPool.Config().MaxConnLifetime.Seconds())
	statsMap["max_connection_idle_time"] = int(store.dbPool.Config().MaxConnIdleTime.Seconds())

	store.logger.Info("resource store - Pool stats", statsMap)
}
