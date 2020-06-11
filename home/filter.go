package home

import (
	"strings"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/AdGuardHome/filters"
)

// Filtering - module object
type Filtering struct {
}

func (f *Filtering) onFiltersChanged(flags uint) {
	switch flags {
	case filters.EventBeforeUpdate:
		//

	case filters.EventAfterUpdate:
		enableFilters(true)
	}
}

// Start - start the module
func (f *Filtering) Start() {
	Context.filters0.AddUser(f.onFiltersChanged)
	Context.filters1.AddUser(f.onFiltersChanged)
	f.RegisterFilteringHandlers()
}

// Close - close the module
func (f *Filtering) Close() {
}

func defaultFilters() []filters.Filter {
	return []filters.Filter{
		{
			ID:      1,
			Enabled: true,
			URL:     "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
			Name:    "AdGuard Simplified Domain Names filter",
		},
		{
			ID:      2,
			Enabled: false,
			URL:     "https://adaway.org/hosts.txt",
			Name:    "AdAway",
		},
		{
			ID:      3,
			Enabled: false,
			URL:     "https://www.malwaredomainlist.com/hostslist/hosts.txt",
			Name:    "MalwareDomainList.com Hosts List",
		},
	}
}

func enableFilters(async bool) {
	var blockFilters []dnsfilter.Filter
	var allowFilters []dnsfilter.Filter
	if config.DNS.FilteringEnabled {
		// convert array of filters

		// add user filter
		userFilter := dnsfilter.Filter{
			ID:   0,
			Data: []byte(strings.Join(config.UserRules, "\n")),
		}
		blockFilters = append(blockFilters, userFilter)

		// add blocklist filters
		list := Context.filters0.List(0)
		for _, f := range list {
			if !f.Enabled || f.RuleCount == 0 {
				continue
			}
			f := dnsfilter.Filter{
				ID:       int64(f.ID),
				FilePath: f.Path,
			}
			blockFilters = append(blockFilters, f)
		}

		// add allowlist filters
		list = Context.filters1.List(0)
		for _, f := range list {
			if !f.Enabled || f.RuleCount == 0 {
				continue
			}
			f := dnsfilter.Filter{
				ID:       int64(f.ID),
				FilePath: f.Path,
			}
			allowFilters = append(allowFilters, f)
		}
	}

	_ = Context.dnsFilter.SetFilters(blockFilters, allowFilters, async)
}
