package unittests

import (
	"fmt"
	"os"
	"testing"

	shared "github.com/geraldhinson/siftd-base/pkg/unitTestsShared"
)

func TestMain(m *testing.M) {
	if err := shared.SetupTestEnvironment(); err != nil {
		fmt.Printf("failed to configure test environment: %v\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}
