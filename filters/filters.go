package filters

import (
	"net/http"
	"time"
)

// Filters - main interface
type Filters interface {
	// Start - start module
	Start()

	// Close - close the module
	Close()

	// WriteDiskConfig - write configuration on disk
	WriteDiskConfig(c *Conf)

	// AddUser - add user handler for notifications
	AddUser(handler EventHandler)

	// List (thread safe)
	List(flags uint) []Filter

	// Add - add filter (thread safe)
	Add(nf Filter) error

	// Delete - remove filter (thread safe)
	Delete(url string) *Filter

	// Modify - set filter properties (thread safe)
	// Return Status* bitarray
	Modify(url string, enabled bool, name string, newURL string) int

	// Refresh - begin filters update procedure
	Refresh(flags uint)
}

// Filter - filter object
type Filter struct {
	ID           uint64 `yaml:"id"`
	Enabled      bool   `yaml:"enabled"`
	Name         string `yaml:"name"`
	URL          string `yaml:"url"`
	LastModified string `yaml:"last_modified"`

	Path string `yaml:"-"`

	RuleCount   uint64    `yaml:"-"`
	LastUpdated time.Time `yaml:"-"`
	nextUpdate  time.Time
}

const (
	// EventBeforeUpdate - this event is signalled before the update procedure renames/removes old filter files
	EventBeforeUpdate = iota
	// EventAfterUpdate - this event is signalled after the update procedure is finished
	EventAfterUpdate
)

// EventHandler - event handler function
type EventHandler func(flags uint)

const (
	// StatusNotFound - not found
	StatusNotFound = 1
	// StatusChangedEnabled - changed 'Enabled'
	StatusChangedEnabled = 2
	// StatusChangedURL - changed 'URL'
	StatusChangedURL = 4
)

// Conf - configuration
type Conf struct {
	FilterDir           string
	UpdateIntervalHours uint32 // 0: disabled
	HTTPClient          *http.Client
	List                []Filter
}

// New - create object
func New(conf Conf) Filters {
	return newFiltersObj(conf)
}
