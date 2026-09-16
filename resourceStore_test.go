package unittests

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
)

type Employee struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// Define struct that embeds ResourceBase
type EmployeeResource struct {
	resourceStore.ResourceBase
	Employee Employee `json:"employee"`
}

func TestEnvironmentVariablesExist(t *testing.T) {
	testService := serviceBase.NewServiceBase()
	if testService == nil {
		t.Fatal("Failed to create service base.")
	}

	configuration := testService.Configuration
	if configuration == nil {
		t.Fatal("Service base returned nil configuration.")
	}

	debugFlagAuth := configuration.GetString(constants.DEBUGSIFTD_AUTH)
	if debugFlagAuth == "" {
		t.Fatal("THe debug flag for auth is not set in the configuration.")
	}
	serviceInstanceName := configuration.GetString(constants.SERVICE_INSTANCE_NAME)
	if serviceInstanceName == "" {
		t.Fatal("Service instance name is not set in the configuration.")
	}
	dbConnectionString := configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString == "" {
		t.Fatal("DB connection string is not set in the configuration.")
	}
	journalPartitionName := configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if journalPartitionName == "" {
		t.Fatal("Journal partition name is not set in the configuration.")
	}
	identityService := configuration.GetString(constants.IDENTITY_SERVICE)
	if identityService == "" {
		t.Fatal("Identity service is not set in the configuration.")
	}
	listenAddress := configuration.GetString(constants.LISTEN_ADDRESS)
	if listenAddress == "" {
		t.Fatal("Listen address is not set in the configuration.")
	}

	calledServices := configuration.GetString(constants.CALLED_SERVICES)
	if calledServices == "" {
		t.Fatal("Called services is not set in the configuration.")
	}
	// check if called services is a valid JSON array
	var stringArray []string
	// Unmarshal the JSON array
	if err := configuration.UnmarshalKey(constants.CALLED_SERVICES, &stringArray); err != nil {
		t.Fatalf("failed unmarshalling called services JSON from env var: %v", err)
	}

}

func TestCreateServiceBase(t *testing.T) {
	service := serviceBase.NewServiceBase()
	if service == nil {
		t.Fatal("Expected non-nil service")
	} else if service.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		t.Errorf("Expected healthy status, got %s", service.HealthStatus.Status)
	}
}

func TestCreateServiceBaseFail(t *testing.T) {
	// override the env variable constants.SERVICE_INSTANCE_NAME
	// to simulate a failure

	validService := serviceBase.NewServiceBase()
	if validService == nil {
		t.Fatal("Failed to create baseline service base.")
	}

	configuration := validService.Configuration
	serviceInstanceName := configuration.GetString(constants.SERVICE_INSTANCE_NAME)
	if serviceInstanceName == "" {
		t.Fatal("Service instance name is not set in the baseline configuration.")
	}

	configuration.Set(constants.SERVICE_INSTANCE_NAME, "")
	defer configuration.Set(constants.SERVICE_INSTANCE_NAME, serviceInstanceName)

	failedService := serviceBase.NewServiceBase()
	if failedService != nil {
		t.Fatal("Expected nil service base when service instance name is missing.")
	}
}

func TestCreateResourceStore(t *testing.T) {
	testService := serviceBase.NewServiceBase()
	if testService == nil {
		t.Fatal("Failed to create baseline service base.")
	}
	configuration := testService.Configuration
	logger := testService.Logger

	store, err := resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err != nil {
		t.Fatalf("Error creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	t.Cleanup(store.Close)

	selectCmd := store.Cmds.GetHealthCheckCommand()
	// check if string contains SELECT 1;
	if selectCmd == "" {
		t.Fatal("Expected non-empty health check command")
	} else if !strings.Contains(selectCmd, "SELECT 1;") {
		t.Errorf("Expected health check command to contain 'SELECT 1;', got %s", selectCmd)
	}
}

func TestDeprecatedNewPostgresResourceStoreWithJournal(t *testing.T) {
	testService := serviceBase.NewServiceBase()
	if testService == nil {
		t.Fatal("Failed to create baseline service base.")
	}

	store, err :=
		resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](
			testService.Configuration,
			testService.Logger,
		)
	if err != nil {
		t.Fatalf(
			"Deprecated NewPostgresResourceStoreWithJournal returned an error: %v",
			err,
		)
	}
	if store == nil {
		t.Fatal(
			"Deprecated NewPostgresResourceStoreWithJournal returned a nil store.",
		)
	}
	t.Cleanup(store.Close)

	if err := store.HealthCheck(); err != nil {
		t.Fatalf(
			"Store created through deprecated constructor failed its health check: %v",
			err,
		)
	}
}

func TestCreateResoureceStoreFail(t *testing.T) {

	testService := serviceBase.NewServiceBase()
	if testService == nil {
		t.Fatal("Failed to create baseline service base.")
	}
	configuration := testService.Configuration
	logger := testService.Logger

	// invalid type passed to NewPostgresJournaledResourceStore. Doesn't include ResourceBase
	aStore, err := resourceStore.NewPostgresJournaledResourceStore[Employee](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught passing using invalid generic type while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if aStore != nil {
		t.Fatal("Expected nil store")
	}

	// nil config parameter
	store, err := resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		nil,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught passing nil config * while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}

	// nil logger parameter
	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		nil,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught passing nil logger * while creating PostgresstoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}

	dbConnectionString := configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString == "" {
		t.Fatal("DB connection string is not set in the configuration.")
	}

	// Set the db connection env var to an empty string
	configuration.Set(constants.DB_CONNECTION_STRING, "")
	defer configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString) // safety net

	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught unset db connection string while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}

	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset := configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// Set the db connection env var to an empty string
	journalPartitionString := configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if journalPartitionString == "" {
		t.Fatal("Journal partition name is not set in the configuration.")
	}

	// Set the journal partition env var to an empty string
	configuration.Set(constants.JOURNAL_PARTITION_NAME, "")
	defer configuration.Set(constants.JOURNAL_PARTITION_NAME, journalPartitionString) // safety net

	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught unset journal partition string while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}

	configuration.Set(constants.JOURNAL_PARTITION_NAME, journalPartitionString)
	journalPartitionStringReset := configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if journalPartitionString != journalPartitionStringReset {
		t.Fatal("journal partition env var was not successfully reset in the configuration.")
	}

	// bogus db connection string
	configuration.Set(constants.DB_CONNECTION_STRING, "bogus connection string")
	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (corrupt connection string) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with non-existent database name
	configuration.Set(constants.DB_CONNECTION_STRING, "user=geraldhinson password=geraldhinson dbname=bogus host=localhost port=5432")
	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (non-existent database) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with failing login
	configuration.Set(constants.DB_CONNECTION_STRING, "user=bogususer password=boguspassword dbname=unittests host=localhost port=5432")
	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (login/password) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with wrong listen port for DB
	configuration.Set(constants.DB_CONNECTION_STRING, "user=bogususer password=boguspassword dbname=unittests host=localhost port=55432")
	store, err = resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
		configuration,
		logger,
		constants.NOUN_DB_POOL_MAX_CONNS,
	)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (port) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if store != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

}

func TestHealthCheck(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	err := store.HealthCheck()
	if err != nil {
		t.Errorf("Error checking health: %s", err)
	}
}

func TestCreateResource(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Alice", Age: 30},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := store.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	if createdResource == nil {
		t.Fatal("Expected non-nil created resource")
	}
	if createdResource.GetResourceBase().Id == "" {
		t.Fatal("Expected non-empty resource ID")
	}
	if createdResource.GetResourceBase().Version != 1 {
		t.Fatalf("Expected version 0, got %d", createdResource.GetResourceBase().Version)
	}
	if createdResource.GetResourceBase().OwnerId != resourceA.OwnerId {
		t.Fatalf("Expected owner ID %s, got %s", resourceA.OwnerId, createdResource.GetResourceBase().OwnerId)
	}
	if createdResource.GetResourceBase().CreatedAt.IsZero() {
		t.Fatal("Expected non-zero CreatedAt timestamp")
	}
	if createdResource.GetResourceBase().UpdatedAt.IsZero() {
		t.Fatal("Expected non-zero UpdatedAt timestamp")
	}
	if createdResource.GetResourceBase().Deleted {
		t.Fatal("Expected Deleted to be false")
	}
}

func TestCreateResourceFails(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Goober", Age: 30},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := store.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	if errmsg != nil {
		t.Fatal("Expected nil errror message")
	}

	resourceDuplicateId := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{
			Id:      createdResource.GetResourceBase().Id,
			OwnerId: "1234"},
		Employee: Employee{Name: "Goober", Age: 30},
	}
	createdResource, status, errmsg = store.CreateResource(resourceDuplicateId, addedSecurityHeader)
	if status != constants.RESOURCE_ALREADY_EXISTS_CODE {
		t.Errorf("Error creating resource - expected duplicate id error: %d, %v", status, errmsg)
		return
	}
	if errmsg == nil {
		t.Fatal("Expected non-nil errror message")
	}
	if createdResource != nil {
		t.Fatal("Expected nil created resource")
	}
}

func TestUpdateResource(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Bob", Age: 40},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := store.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	resourceA.Employee.Name = "Bob's Uncle"
	updatedResource, status, errmsg := store.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error updating resource: %d, %v", status, errmsg)
		return
	}
	if updatedResource == nil {
		t.Fatal("Expected non-nil updated resource")
	}
	if updatedResource.GetResourceBase().Id != createdResource.GetResourceBase().Id {
		t.Fatalf("Expected resource ID %s, got %s", createdResource.GetResourceBase().Id, updatedResource.GetResourceBase().Id)
	}
	if updatedResource.GetResourceBase().Version != 2 {
		t.Fatalf("Expected version 2, got %d", updatedResource.GetResourceBase().Version)
	}
	if updatedResource.GetResourceBase().OwnerId != resourceA.OwnerId {
		t.Fatalf("Expected owner ID %s, got %s", resourceA.OwnerId, updatedResource.GetResourceBase().OwnerId)
	}
	if updatedResource.GetResourceBase().CreatedAt.IsZero() {
		t.Fatal("Expected non-zero CreatedAt timestamp")
	}
	if updatedResource.GetResourceBase().UpdatedAt.IsZero() {
		t.Fatal("Expected non-zero UpdatedAt timestamp")
	}
	if updatedResource.GetResourceBase().Deleted {
		t.Fatal("Expected Deleted to be false")
	}
	if updatedResource.(*EmployeeResource).Employee.Name != "Bob's Uncle" {
		t.Fatalf("Expected employee name 'Bob's Uncle', got %s", updatedResource.(*EmployeeResource).Employee.Name)
	}
	if updatedResource.(*EmployeeResource).Employee.Age != 40 {
		t.Fatalf("Expected employee age 40, got %d", updatedResource.(*EmployeeResource).Employee.Age)
	}
}

func TestUpdateResourceFails(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Bob", Age: 40},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := store.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	if createdResource == nil {
		t.Fatal("Expected non-nil created resource")
	}

	// Test invalid version
	resourceA.Employee.Name = "Bob's Aunt"
	resourceA.ResourceBase.Version = 2 // Set version to 1 to simulate a conflict
	updatedResource, status, errmsg := store.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
	if status != constants.RESOURCE_BAD_REQUEST_CODE {
		t.Errorf("Error updating resource - wrong status returned for invalid version test: %d, %v", status, errmsg)
		return
	}
	if errmsg == nil {
		t.Fatal("Expected non-nil error message for invalid version test")
	}
	if updatedResource != nil {
		t.Fatal("Expected nil updated resource for invalid version test")
	}

	// Test invalid owner ID
	resourceA.Employee.Name = "Bob's Aunt"
	resourceA.ResourceBase.Version = 1       // Set version to 1 to simulate a conflict
	var BadOwnerId = "NON-EXISTENT-OWNER-ID" // Set owner ID to a non-existent value
	updatedResource, status, errmsg = store.UpdateResource(resourceA, BadOwnerId, resourceA.Id, addedSecurityHeader)
	if status != constants.RESOURCE_BAD_REQUEST_CODE {
		t.Errorf("Error updating resource - wrong status returned for invalid ownerId param test: %d, %v", status, errmsg)
		return
	}
	if errmsg == nil {
		t.Fatal("Expected non-nil error message for invalid ownerId param test")
	}
	if updatedResource != nil {
		t.Fatal("Expected nil updated resource for invalid ownerId param test")
	}

	// test invalid ID in body
	resourceA.Employee.Name = "Bob's Aunt"
	resourceA.ResourceBase.Version = 1
	var saveResourceId = resourceA.Id
	resourceA.Id = "NON-EXISTENT-ID" // Set ID to a non-existent value
	updatedResource, status, errmsg = store.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
	if status != constants.RESOURCE_BAD_REQUEST_CODE {
		t.Errorf("Error updating resource - wrong status returned for invalid id in body test: %d, %v", status, errmsg)
		return
	}
	if errmsg == nil {
		t.Fatal("Expected non-nil error message for invalid id in body test")
	}
	if updatedResource != nil {
		t.Fatal("Expected nil updated resource for invalid id in body test")
	}
	resourceA.Id = saveResourceId // Reset ID to original value

	// test invalid ID param - doesn't match ID in body
	resourceA.Employee.Name = "Bob's Aunt"
	resourceA.ResourceBase.Version = 1
	var BadIdParam = "NON-EXISTENT-ID" // Set ID to a non-existent value
	updatedResource, status, errmsg = store.UpdateResource(resourceA, resourceA.OwnerId, BadIdParam, addedSecurityHeader)
	if status != constants.RESOURCE_BAD_REQUEST_CODE {
		t.Errorf("Error updating resource - wrong status returned for invalid id param test: %d, %v", status, errmsg)
		return
	}
	if errmsg == nil {
		t.Fatal("Expected non-nil error message for invalid id param test")
	}
	if updatedResource != nil {
		t.Fatal("Expected nil updated resource for invalid id param test")
	}

}

func TestGetById(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Danny", Age: 37},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := store.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}

	var fetchedResource EmployeeResource
	status, errmsg = store.GetById(createdResource.GetResourceBase().OwnerId, createdResource.GetResourceBase().Id, &fetchedResource)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error getting resource by id: %d, %v", status, errmsg)
		return
	}
	if fetchedResource.Employee.Name != "Danny" {
		t.Fatalf("Expected employee name 'Danny', got %s", fetchedResource.Employee.Name)
	}
	if fetchedResource.Employee.Age != 37 {
		t.Fatalf("Expected employee age 37, got %d", fetchedResource.Employee.Age)
	}
}

func TestGetByIdFail(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{Id: "BogusId", OwnerId: "1234"},
		Employee:     Employee{Name: "Danny", Age: 37},
	}

	var fetchedResource EmployeeResource
	status, errmsg := store.GetById(resourceA.OwnerId, resourceA.Id, &fetchedResource)
	if status != constants.RESOURCE_NOT_FOUND_ERROR_CODE {
		t.Errorf("Error found resource by bogus id: %d, %v", status, errmsg)
		return
	}
}

func TestGetByOwnerId(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	var fetchedResources = []EmployeeResource{}
	status, errmsg := store.GetByOwnerId("1234", &fetchedResources)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error getting resource by owner id: %d, %v", status, errmsg)
		return
	}
	if len(fetchedResources) == 0 {
		t.Fatal("Expected non-empty fetched resources")
	}
	// loop through the fetched resources and check if the owner ID matches
	for _, fetchedResource := range fetchedResources {
		if fetchedResource.GetResourceBase().OwnerId != "1234" {
			t.Fatalf("Expected owner ID '1234', got %s", fetchedResource.GetResourceBase().OwnerId)
		}
	}
}

func TestGetJournalMaxClock(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	var maxClock uint64
	err := store.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}
	if maxClock == 0 {
		t.Fatal("Expected non-zero max clock")
	}
}

func TestGetJournalChanges(t *testing.T) {
	store := newTestResourceStore(t)
	if store == nil {
		t.Fatal("Expected non-nil store")
	}

	var maxClock uint64
	err := store.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}

	if maxClock > 0 {
		var journalEntries = []resourceStore.ResourceJournalEntry{}
		status, err := store.GetJournalChanges(1, int64(maxClock), &journalEntries) // TODO: fix the type of limit in the API
		if status != constants.RESOURCE_OK_CODE {
			t.Fatalf("Error getting journal entries - expected status %d, got %d", constants.RESOURCE_OK_CODE, status)
		}
		if err != nil {
			t.Errorf("Error getting journal entries: %v", err)
			return
		}
		// make sure last one has clock equal to max clock
		if journalEntries[(len(journalEntries))-1].Clock != maxClock {
			t.Fatal("Expected count of journal entries returned to be equal to max clock")
		}

		// simple validation of json marshalling of a journal entry
		jsonBytes, err := json.Marshal(journalEntries[0])
		//		jsonBytes, err := journalEntries[0].MarshalJSON()	// test without, then delete this
		if err != nil {
			t.Errorf("Error marshaling journal entry to JSON: %v", err)
			return
		}
		if len(jsonBytes) == 0 {
			t.Fatal("Expected non-empty JSON bytes")
		}
		if string(jsonBytes) == "{}" {
			t.Fatal("Expected non-empty JSON bytes")
		}
		if !strings.Contains(string(jsonBytes), "clock") {
			t.Fatal("Expected JSON bytes to contain 'clock'")
		}
		if !strings.Contains(string(jsonBytes), "updatedAt") {
			t.Fatal("Expected JSON bytes to contain 'updatedAt'")
		}
		if !strings.Contains(string(jsonBytes), "partitionName") {
			t.Fatal("Expected JSON bytes to contain 'partitionName'")
		}
		if !strings.Contains(string(jsonBytes), "resource") {
			t.Fatal("Expected JSON bytes to contain 'resource'")
		}
	}
}

func newTestResourceStore(
	t *testing.T,
) *resourceStore.PostgresResourceStoreWithJournal[EmployeeResource] {
	t.Helper()

	service := serviceBase.NewServiceBase()
	if service == nil {
		t.Fatal("Failed to create service base.")
	}

	store, err :=
		resourceStore.NewPostgresJournaledResourceStore[EmployeeResource](
			service.Configuration,
			service.Logger,
			constants.NOUN_DB_POOL_MAX_CONNS,
		)
	if err != nil {
		t.Fatalf("Failed to create resource store: %v", err)
	}

	t.Cleanup(store.Close)

	return store
}

// TODO: add a 'Delete' (aka UpdateResource with Deleted = true) test
// TODO: add tests to catch if someone has corrupted the JSON stored in the DB tables
// TODO: add tests to catch if database is down or goes down after successful connection
// TODO: do auth, helpers, serviceBase tests, etc.
