package unittests

import (
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

var ServiceBase *serviceBase.ServiceBase
var ResourceStore *resourceStore.PostgresResourceStoreWithJournal[EmployeeResource]

func TestCreateServiceBase(t *testing.T) {

	ServiceBase = serviceBase.NewServiceBase()
	if ServiceBase == nil {
		t.Fatal("Expected non-nil serviceBase")
	} else if ServiceBase.HealthStatus.Status != constants.HEALTH_STATUS_HEALTHY {
		t.Errorf("Expected healthy status, got %s", ServiceBase.HealthStatus.Status)
	}
}

func TestCreateResoureceStore(t *testing.T) {

	var err error
	ResourceStore, err = resourceStore.NewPostgresResourceStoreWithJournal[EmployeeResource](ServiceBase.Configuration, ServiceBase.Logger)
	if err != nil {
		t.Fatalf("Error creating PostgresResourceStoreWithJournal: %v", err)
	}
	if ResourceStore == nil {
		t.Fatal("Expected non-nil store")
	}
	selectCmd := ResourceStore.Cmds.GetHealthCheckCommand()
	// check if string contains SELECT 1;
	if selectCmd == "" {
		t.Fatal("Expected non-empty health check command")
	} else if !strings.Contains(selectCmd, "SELECT 1;") {
		t.Errorf("Expected health check command to contain 'SELECT 1;', got %s", selectCmd)
	}
}

func TestHealthCheck(t *testing.T) {
	err := ResourceStore.HealthCheck()
	if err != nil {
		t.Errorf("Error checking health: %s", err)
	}
}

func TestCreateResource(t *testing.T) {
	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Alice", Age: 30},
	}

	createdResource, status, errmsg := ResourceStore.CreateResource(resourceA)
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

func TestUpdateResource(t *testing.T) {
	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Bob", Age: 40},
	}

	createdResource, status, errmsg := ResourceStore.CreateResource(resourceA)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}
	resourceA.Employee.Name = "Bob's Uncle"
	updatedResource, status, errmsg := ResourceStore.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id)
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

func TestGetById(t *testing.T) {
	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Danny", Age: 37},
	}

	createdResource, status, errmsg := ResourceStore.CreateResource(resourceA)
	if status != constants.RESOURCE_OK_CODE {
		t.Errorf("Error creating resource: %d, %v", status, errmsg)
		return
	}

	var fetchedResource EmployeeResource
	status, errmsg = ResourceStore.GetById(createdResource.GetResourceBase().Id, &fetchedResource)
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

func TestGetByOwnerId(t *testing.T) {
	var fetchedResources = []EmployeeResource{}
	status, errmsg := ResourceStore.GetByOwnerId("1234", &fetchedResources)
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
	var maxClock uint64
	err := ResourceStore.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}
	if maxClock == 0 {
		t.Fatal("Expected non-zero max clock")
	}
}

func TestGetJournalChanges(t *testing.T) {
	var maxClock uint64
	err := ResourceStore.GetJournalMaxClock(&maxClock)
	if err != nil {
		t.Errorf("Error getting journal max clock: %v", err)
		return
	}

	if maxClock > 0 {
		var journalEntries = []resourceStore.ResourceJournalEntry{}
		err := ResourceStore.GetJournalChanges(1, int64(maxClock), &journalEntries) // TODO: fix the type of limit in the API
		if err != nil {
			t.Errorf("Error getting journal entries: %v", err)
			return
		}
		// make sure last one has clock equal to max clock
		if journalEntries[(len(journalEntries))-1].Clock != maxClock {
			t.Fatal("Expected count of journal entries returned to be equal to max clock")
		}

		// simple validation of json marshalling of a journal entry
		jsonBytes, err := journalEntries[0].MarshalJSON()
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
		if !strings.Contains(string(jsonBytes), "createdAt") {
			t.Fatal("Expected JSON bytes to contain 'createdAt'")
		}
		if !strings.Contains(string(jsonBytes), "partitionName") {
			t.Fatal("Expected JSON bytes to contain 'partitionName'")
		}
		if !strings.Contains(string(jsonBytes), "resource") {
			t.Fatal("Expected JSON bytes to contain 'resource'")
		}

	}
}
