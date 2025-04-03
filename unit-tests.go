package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/geraldhinson/siftd-base/pkg/constants"
	"github.com/geraldhinson/siftd-base/pkg/resourceStore"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// TODO: convert this to use the testing framework from the digital ocean tutorial
// https://www.digitalocean.com/community/tutorials/how-to-write-unit-tests-in-go-using-go-test-and-the-testing-package
// TODO: also add an equivalent for the query service package
//

type Employee struct {
	Name string `json:"name"`
	Age  int    `json:"age"`
}

// Define struct that embeds ResourceBase
type EmployeeResource struct {
	resourceStore.ResourceBase
	Employee Employee `json:"employee"`
}

func main() {
	logger, configuration := setup()
	if logger == nil || configuration == nil {
		fmt.Println("Setup failed for query service. Shutting down.")
		return
	}

	store, err := resourceStore.NewPostgresResourceStoreWithJournal[Employee](configuration, logger)
	if err != nil {
		fmt.Println("Error creating PostgresResourceStoreWithJournal:", err)
		return
	}

	// Example usage for struct A
	resourceA := &EmployeeResource{
		ResourceBase: resourceStore.ResourceBase{OwnerId: "1234"},
		Employee:     Employee{Name: "Alice", Age: 30},
	}

	jsonBytes, err := json.Marshal(resourceA)
	if err != nil {
		fmt.Println("Error marshalling resource:", err)
		return
	}
	fmt.Println(string(jsonBytes))

	err = store.HealthCheck()
	if err != nil {
		fmt.Println("Error checking health:", err)
		return
	}

	createdResource, status, errmsg := store.CreateResource(resourceA)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error creating resource:", status, errmsg)
		return
	}
	fmt.Println(createdResource)

	_, status, errmsg = store.CreateResource(createdResource)
	if status != constants.RESOURCE_ALREADY_EXISTS_CODE {
		fmt.Println("Error creating resource:", status, errmsg)
		return
	}

	resourceA.Employee.Name = "Bob"
	updatedResource, status, errmsg := store.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error updating resource:", status, errmsg)
		return
	}
	fmt.Println(updatedResource)

	resourceA.Version = 1
	updatedResource2, status, errmsg := store.UpdateResource(resourceA, resourceA.OwnerId, resourceA.Id)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error updating resource:", status, errmsg)
		return
	}
	fmt.Println(updatedResource2)

	var fetchedResource Employee
	status, errmsg = store.GetById(createdResource.GetResourceBase().Id, &fetchedResource)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error getting resource by id:", status, errmsg)
		return
	}
	fmt.Println(fetchedResource)

	var fetchedResource2 Employee
	status, errmsg = store.GetById("NON-EXISTENT-ID", &fetchedResource2)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error getting resource by id:", status, errmsg)
	}
	fmt.Println(fetchedResource2)

	var fetchedResources = []Employee{}
	status, errmsg = store.GetByOwnerId("1234", &fetchedResources)
	if status != constants.RESOURCE_OK_CODE {
		fmt.Println("Error getting resource by id:", status, errmsg)
		return
	}
	fmt.Println(fetchedResources)

	var journalEntries = []resourceStore.ResourceJournalEntry{}
	err = store.GetJournalChanges(1, 10, &journalEntries)
	if err != nil {
		fmt.Println("Error getting journal entries:", err)
		return
	}
	//	fmt.Println(journalEntries)

	var maxClock uint64
	err = store.GetJournalMaxClock(&maxClock)
	if err != nil {
		fmt.Println("Error getting journal entries:", err)
		return
	}
	fmt.Println(maxClock)
}

func setup() (*logrus.Logger, *viper.Viper) {
	// Initialize logger
	logger := logrus.New()
	if logger == nil {
		fmt.Println("Failed to create logger for query service. Shutting down.")
		return nil, nil
	}

	// Initialize configuration
	viper.AddConfigPath(os.Getenv("RESDIR_PATH"))
	viper.SetConfigFile("app.env")
	viper.AutomaticEnv() // overrides app.env with environment variables if same name found
	err := viper.ReadInConfig()
	if err != nil {
		logger.Info("Failed to read config for query service. Shutting down.")
		return nil, nil
	}
	configuration := viper.GetViper()

	return logger, configuration
}
