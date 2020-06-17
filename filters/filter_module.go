package filters

import (
	"net/http"
	"path/filepath"
)

// Filtering - module object
type Filtering struct {
	dnsBlocklist Filters // DNS blocklist filters
	dnsAllowlist Filters // DNS allowlist filters
	Proxylist Filters // MITM Proxy filtering module

	conf ModuleConf
}

// ModuleConf - module config
type ModuleConf struct {
	Enabled             bool
	UpdateIntervalHours uint32 // 0: disabled
	HTTPClient          *http.Client
	DataDir             string
	DNSBlocklist        []Filter
	DNSAllowlist        []Filter
	Proxylist           []Filter
	UserRules           []string

	// Called when the configuration is changed by HTTP request
	ConfigModified func()

	// Register an HTTP handler
	HTTPRegister func(string, string, func(http.ResponseWriter, *http.Request))
}

// NewModule - create module
func NewModule(conf ModuleConf) *Filtering {
	f := Filtering{}
	f.conf = conf

	fconf := Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_dnsblock")
	fconf.List = conf.DNSBlocklist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.dnsBlocklist = New(fconf)

	fconf = Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_dnsallow")
	fconf.List = conf.DNSAllowlist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.dnsAllowlist = New(fconf)

	fconf = Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_mitmproxy")
	fconf.List = conf.Proxylist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.Proxylist = New(fconf)

	return &f
}

const (
	DNSBlocklist = iota
	DNSAllowlist
	Proxylist
)

func stringArrayDup(a []string) []string {
	a2 := make([]string, len(a))
	copy(a2, a)
	return a2
}

// WriteDiskConfig - write configuration data
func (f *Filtering) WriteDiskConfig(mc *ModuleConf) {
	mc.Enabled = f.conf.Enabled
	mc.UpdateIntervalHours = f.conf.UpdateIntervalHours
	mc.UserRules = stringArrayDup(f.conf.UserRules)

	c := Conf{}
	f.dnsBlocklist.WriteDiskConfig(&c)
	mc.DNSBlocklist = c.List

	c = Conf{}
	f.dnsAllowlist.WriteDiskConfig(&c)
	mc.DNSAllowlist = c.List

	c = Conf{}
	f.Proxylist.WriteDiskConfig(&c)
	mc.Proxylist = c.List
}

// GetList - get specific filter list
func (f *Filtering) GetList(t uint32) Filters {
	switch t {
	case DNSBlocklist:
		return f.dnsBlocklist
	case DNSAllowlist:
		return f.dnsAllowlist
	case Proxylist:
		return f.Proxylist
	}
	return nil
}

// Start - start module
func (f *Filtering) Start() {
	f.dnsBlocklist.Start()
	f.dnsAllowlist.Start()
	f.Proxylist.Start()
	f.registerWebHandlers()
}

// Close - close the module
func (f *Filtering) Close() {
}
