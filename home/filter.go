package home

import (
	"strings"

	"github.com/AdguardTeam/AdGuardHome/dnsfilter"
	"github.com/AdguardTeam/AdGuardHome/filters"
)

// Filtering - module object
type Filtering struct {
}

// Start - start the module
func (f *Filtering) Start() {
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
	var filters []dnsfilter.Filter
	var whiteFilters []dnsfilter.Filter
	if config.DNS.FilteringEnabled {
		// convert array of filters

		f := dnsfilter.Filter{
			ID:   0,
			Data: []byte(strings.Join(config.UserRules, "\n")),
		}
		filters = append(filters, f)

		filtrs := Context.filters0.List(0)
		for _, filter := range filtrs {
			if !filter.Enabled {
				continue
			}
			f := dnsfilter.Filter{
				ID:       int64(filter.ID),
				FilePath: filter.Path,
			}
			filters = append(filters, f)
		}

		filtrs = Context.filters1.List(0)
		for _, filter := range filtrs {
			if !filter.Enabled {
				continue
			}
			f := dnsfilter.Filter{
				ID:       int64(filter.ID),
				FilePath: filter.Path,
			}
			whiteFilters = append(whiteFilters, f)
		}
	}

	_ = Context.dnsFilter.SetFilters(filters, whiteFilters, async)
}
