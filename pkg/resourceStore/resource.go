package resourceStore

import (
	"encoding/json"
	"time"
)

type ResourceBase struct {
	Id        string    `json:"id"`
	OwnerId   string    `json:"ownerId"`
	Version   uint      `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
	Deleted   bool      `json:"deleted"`
}

func (r *ResourceBase) GetResourceBase() *ResourceBase {
	return r
}

// IResource is an interface that any resource can implement
type IResource interface {
	GetResourceBase() *ResourceBase
}

type ResourceJournalEntry struct {
	Clock         uint64
	Resource      []byte
	CreatedAt     time.Time
	PartitionName string
}

// Custom MarshalJSON to manually add the Resource field as-is so we don't have to hydrate it just to marshal it again
// TODO: Consider if I should do the same for the noun gets? Worth chasing?
func (rj ResourceJournalEntry) MarshalJSON() ([]byte, error) {
	// Create a map with the fields you want to include in the output JSON
	// Manually include the Resource field as-is
	result := map[string]interface{}{
		"clock":         rj.Clock,
		"createdAt":     rj.CreatedAt,
		"partitionName": rj.PartitionName,
		"resource":      json.RawMessage(rj.Resource), // Use RawMessage to avoid re-marshaling
	}

	// Marshal the map to JSON
	return json.Marshal(result)
}
