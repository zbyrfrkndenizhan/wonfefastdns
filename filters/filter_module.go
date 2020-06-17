package filters

import (
	"net/http"
	"path/filepath"
)

// Filtering - module object
type Filtering struct {
	filters0 Filters // DNS blocklist filters
	filters1 Filters // DNS allowlist filters
	filters2 Filters // MITM Proxy filtering module

	conf ModuleConf
}

type ModuleConf struct {
	DataDir             string
	UpdateIntervalHours uint32 // 0: disabled
	HTTPClient          *http.Client
	DNSBlocklist        []Filter
	DNSAllowlist        []Filter
	Proxylist           []Filter

	// Called when the configuration is changed by HTTP request
	ConfigModified func()

	// Register an HTTP handler
	HTTPRegister func(string, string, func(http.ResponseWriter, *http.Request))
}

// Init - init the module
func (f *Filtering) Init(conf ModuleConf) {
	f.conf = conf

	fconf := Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_dnsblock")
	fconf.List = conf.DNSBlocklist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.filters0 = New(fconf)

	fconf = Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_dnsallow")
	fconf.List = conf.DNSAllowlist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.filters1 = New(fconf)

	fconf = Conf{}
	fconf.FilterDir = filepath.Join(conf.DataDir, "filters_mitmproxy")
	fconf.List = conf.Proxylist
	fconf.UpdateIntervalHours = conf.UpdateIntervalHours
	fconf.HTTPClient = conf.HTTPClient
	f.filters2 = New(fconf)
}

const (
	DNSBlocklist = iota
	DNSAllowlist
	Proxylist
)

func (f *Filtering) WriteDiskConfig(t uint32, c *Conf) {
	switch t {
	case DNSBlocklist:
		f.filters0.WriteDiskConfig(c)
	case DNSAllowlist:
		f.filters1.WriteDiskConfig(c)
	case Proxylist:
		f.filters2.WriteDiskConfig(c)
	}
}

func (f *Filtering) GetList(t uint32) Filters {
	switch t {
	case DNSBlocklist:
		return f.filters0
	case DNSAllowlist:
		return f.filters1
	case Proxylist:
		return f.filters2
	}
	return nil
}

func (f *Filtering) Start() {
	f.filters0.Start()
	f.filters1.Start()
	f.filters2.Start()
	f.registerWebHandlers()
}

// Close - close the module
func (f *Filtering) Close() {
}
