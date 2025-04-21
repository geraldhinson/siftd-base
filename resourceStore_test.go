package unittests

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/geraldhinson/siftd-base/pkg/serviceBase"
	"github.com/spf13/viper"
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

var gServiceBase *serviceBase.ServiceBase
var gResourceStore *resourceStore.PostgresResourceStoreWithJournal[EmployeeResource]

func setupEnvVars(t *testing.T) *viper.Viper {
	// Initialize configuration
	viper.AddConfigPath(os.Getenv("RESDIR_PATH"))
	viper.SetConfigFile("app.env")
	viper.AutomaticEnv() // overrides app.env with environment variables if same name found
	err := viper.ReadInConfig()
	if err != nil {
		t.Error("Failed to read config for service.")
		return nil
	}
	configuration := viper.GetViper()

	return configuration
}

func TestEnvironmentVariablesExist(t *testing.T) {
	configuration := setupEnvVars(t)
	if configuration == nil {
		t.Fatal("Failed to read config for service.")
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
	if err := viper.UnmarshalKey(constants.CALLED_SERVICES, &stringArray); err != nil {
		t.Fatalf("failed unmarshalling called services JSON from env var: %v", err)
	}

}
func TestCreateServiceBase(t *testing.T) {
	gServiceBase = serviceBase.NewServiceBase()
	if gServiceBase == nil {
		t.Fatal("Expected non-nil serviceBase")
	} else if gServiceBase.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		t.Errorf("Expected healthy status, got %s", gServiceBase.HealthStatus.Status)
	}
}

func TestCreateServiceBaseFail(t *testing.T) {
	// override the env variable constants.SERVICE_INSTANCE_NAME
	// to simulate a failure

	configuration := setupEnvVars(t)
	if configuration == nil {
		t.Fatal("Failed to read config for service.")
		return
	}
	// Get the service instance name from the configuration and unset it
	serviceInstanceName := configuration.GetString(constants.SERVICE_INSTANCE_NAME)
	if serviceInstanceName == "" {
		t.Fatal("Service instance name is not set in the configuration.")
	}
	// Set the service instance name to an empty string
	configuration.Set(constants.SERVICE_INSTANCE_NAME, "")

	ServiceBase := serviceBase.NewServiceBase()
	if ServiceBase != nil {
		t.Fatal("Expected nil serviceBase")
	}

	// Reset the service instance name to the original value
	configuration.Set(constants.SERVICE_INSTANCE_NAME, serviceInstanceName)
	serviceInstanceNameReset := configuration.GetString(constants.SERVICE_INSTANCE_NAME)
	if serviceInstanceName != serviceInstanceNameReset {
		t.Fatal("Service instance name was not successfully reset in the configuration.")
	}

}

func TestCreateResoureceStore(t *testing.T) {

	var err error
	gResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err != nil {
		t.Fatalf("Error creating PostgresResourceStoreWithJournal: %v", err)
	}
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}
	selectCmd := gResourceStore.Cmds.GetHealthCheckCommand()
	// check if string contains SELECT 1;
	if selectCmd == "" {
		t.Fatal("Expected non-empty health check command")
	} else if !strings.Contains(selectCmd, "SELECT 1;") {
		t.Errorf("Expected health check command to contain 'SELECT 1;', got %s", selectCmd)
	}
}

func TestCreateResoureceStoreFail(t *testing.T) {

	// invalid type passed to NewPostgresResourceStoreWithJournal. Doesn't include ResourceBase
	var err error
	aResourceStore, err := resourceStore.NewPostgresResourceStoreWithJournal[Employee](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught passing using invalid generic type while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if aResourceStore != nil {
		t.Fatal("Expected nil store")
	}

	// nil parameter
	ResourceStore, err := resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](nil, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught passing nil config * while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}

	// nil parameter
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, nil)
	if err == nil {
		t.Fatalf("Error not caught passing nil logger * while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}

	configuration := setupEnvVars(t)
	if configuration == nil {
		t.Fatal("Failed to read config for service.")
	}
	dbConnectionString := configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString == "" {
		t.Fatal("DB connection string is not set in the configuration.")
	}

	// Set the db connection env var to an empty string
	configuration.Set(constants.DB_CONNECTION_STRING, "")

	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught unset db connection string while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
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

	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught unset journal partition string while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}

	configuration.Set(constants.JOURNAL_PARTITION_NAME, journalPartitionString)
	journalPartitionStringReset := configuration.GetString(constants.JOURNAL_PARTITION_NAME)
	if journalPartitionString != journalPartitionStringReset {
		t.Fatal("journal partition env var was not successfully reset in the configuration.")
	}

	// bogus db connection string
	configuration.Set(constants.DB_CONNECTION_STRING, "bogus connection string")
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (corrupt connection string) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with non-existent database name
	configuration.Set(constants.DB_CONNECTION_STRING, "user=geraldhinson password=geraldhinson dbname=bogus host=localhost port=5432")
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (non-existent database) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with failing login
	configuration.Set(constants.DB_CONNECTION_STRING, "user=bogususer password=boguspassword dbname=unittests host=localhost port=5432")
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (login/password) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

	// valid db connection string, but with wrong listen port for DB
	configuration.Set(constants.DB_CONNECTION_STRING, "user=bogususer password=boguspassword dbname=unittests host=localhost port=55432")
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](gServiceBase.Configuration, gServiceBase.Logger)
	if err == nil {
		t.Fatalf("Error not caught bogus db connection string (port) while creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore != nil {
		t.Fatal("Expected nil store")
	}
	configuration.Set(constants.DB_CONNECTION_STRING, dbConnectionString)
	dbConnectionStringReset = configuration.GetString(constants.DB_CONNECTION_STRING)
	if dbConnectionString != dbConnectionStringReset {
		t.Fatal("database connection env var was not successfully reset in the configuration.")
	}

}

func TestHealthCheck(t *testing.T) {
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	err := gResourceStore.HealthCheck()
	if err != nil {
		t.Errorf("Error checking health: %s", err)
	}
}

func TestCreateResource(t *testing.T) {
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Alice", Age: 30},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := gResourceStore.CreateResource(resourceA, addedSecurityHeader)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Goober", Age: 30},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := gResourceStore.CreateResource(resourceA, addedSecurityHeader)
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
	createdResource, status, errmsg = gResourceStore.CreateResource(resourceDuplicateId, addedSecurityHeader)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Bob", Age: 40},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := gResourceStore.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	resourceA.Employee.Name = "Bob's Uncle"
	updatedResource, status, errmsg := gResourceStore.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Bob", Age: 40},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := gResourceStore.CreateResource(resourceA, addedSecurityHeader)
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
	updatedResource, status, errmsg := gResourceStore.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
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
	updatedResource, status, errmsg = gResourceStore.UpdateResource(resourceA, BadOwnerId, resourceA.Id, addedSecurityHeader)
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
	updatedResource, status, errmsg = gResourceStore.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id, addedSecurityHeader)
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
	updatedResource, status, errmsg = gResourceStore.UpdateResource(resourceA, resourceA.OwnerId, BadIdParam, addedSecurityHeader)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Danny", Age: 37},
	}

	// this simulates the additional auth token that is added to the header by the security layer
	addedSecurityHeader := resourceA.ResourceBase.OwnerId + ":" // owner w/o impersonation

	createdResource, status, errmsg := gResourceStore.CreateResource(resourceA, addedSecurityHeader)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}

	var fetchedResource EmployeeResource
	status, errmsg = gResourceStore.GetById(createdResource.GetResourceBase().Id, createdResource.GetResourceBase().OwnerId, &fetchedResource)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{Id: "BogusId", OwnerId: "1234"},
		Employee:     Employee{Name: "Danny", Age: 37},
	}

	var fetchedResource EmployeeResource
	status, errmsg := gResourceStore.GetById(resourceA.Id, resourceA.OwnerId, &fetchedResource)
	if status != constants.RESOURCE_NOT_FOUND_ERROR_CODE {
		t.Errorf("Error found resource by bogus id: %d, %v", status, errmsg)
		return
	}
}

func TestGetByOwnerId(t *testing.T) {
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	var fetchedResources = []EmployeeResource{}
	status, errmsg := gResourceStore.GetByOwnerId("1234", &fetchedResources)
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
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	var maxClock uint64
	err := gResourceStore.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}
	if maxClock == 0 {
		t.Fatal("Expected non-zero max clock")
	}
}

func TestGetJournalChanges(t *testing.T) {
	if gResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}

	var maxClock uint64
	err := gResourceStore.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}

	if maxClock > 0 {
		var journalEntries = []resourceStore.ResourceJournalEntry{}
		err := gResourceStore.GetJournalChanges(1, int64(maxClock), &journalEntries) // TODO: fix the type of limit in the API
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

// TODO: add a 'Delete' (aka UpdateResource with Deleted = true) test
// TODO: add tests to catch if someone has corrupted the JSON stored in the DB tables
// TODO: add tests to catch if database is down or goes down after successful connection
// TODO: do auth, helpers, serviceBase tests, etc.
