package home

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/filters"
	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
)

// Print to log and set HTTP error message
func httpError2(r *http.Request, w http.ResponseWriter, code int, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	log.Info("Filters: %s %s: %s", r.Method, r.URL, text)
	http.Error(w, text, code)
}

// IsValidURL - return TRUE if URL or file path is valid
func IsValidURL(rawurl string) bool {
	if filepath.IsAbs(rawurl) {
		// this is a file path
		return util.FileExists(rawurl)
	}

	url, err := url.ParseRequestURI(rawurl)
	if err != nil {
		return false //Couldn't even parse the rawurl
	}
	if len(url.Scheme) == 0 {
		return false //No Scheme found
	}
	return true
}

func getFilterModule(t string) filters.Filters {
	switch t {

	case "blocklist":
		return Context.filters0
	case "whitelist":
		return Context.filters1

	case "proxylist":
		return Context.filters2

	default:
		return nil
	}
}

func restartMods(t string) error {
	switch t {

	case "blocklist",
		"whitelist":
		enableFilters(true)

	case "proxylist":
		Context.mitmProxy.Close()
		return Context.mitmProxy.Restart()
	}

	return nil
}

func (f *Filtering) handleFilterAdd(w http.ResponseWriter, r *http.Request) {
	type reqJSON struct {
		Name string `json:"name"`
		URL  string `json:"url"`
		Type string `json:"type"`
	}
	req := reqJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	filterN := getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	filt := filters.Filter{
		Enabled: true,
		Name:    req.Name,
		URL:     req.URL,
	}
	err = filterN.Add(filt)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "add filter: %s", err)
		return
	}

	onConfigModified()

	err = restartMods(req.Type)
	if err != nil {
		httpError2(r, w, http.StatusInternalServerError, "restart: %s", err)
		return
	}
}

func (f *Filtering) handleFilterRemove(w http.ResponseWriter, r *http.Request) {
	type reqJSON struct {
		URL  string `json:"url"`
		Type string `json:"type"`
	}
	req := reqJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	filterN := getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	removed := filterN.Delete(req.URL)
	if removed == nil {
		httpError2(r, w, http.StatusInternalServerError, "no filter with such URL")
		return
	}

	onConfigModified()

	if removed.Enabled {
		err = restartMods(req.Type)
		if err != nil {
			httpError2(r, w, http.StatusInternalServerError, "restart: %s", err)
			// fallthrough
		}
	}

	err = os.Remove(removed.Path)
	if err != nil {
		log.Error("os.Remove: %s", err)
	}
}

func (f *Filtering) handleFilterModify(w http.ResponseWriter, r *http.Request) {
	type propsJSON struct {
		Name    string `json:"name"`
		URL     string `json:"url"`
		Enabled bool   `json:"enabled"`
	}
	type reqJSON struct {
		URL  string    `json:"url"`
		Type string    `json:"type"`
		Data propsJSON `json:"data"`
	}
	req := reqJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	filterN := getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	st, _, err := filterN.Modify(req.URL, req.Data.Enabled, req.Data.Name, req.Data.URL)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "%s", err)
		return
	}

	onConfigModified()

	if st == filters.StatusChangedEnabled ||
		st == filters.StatusChangedURL {

		// TODO filters.StatusChangedURL: delete old file

		err = restartMods(req.Type)
		if err != nil {
			httpError2(r, w, http.StatusInternalServerError, "restart: %s", err)
			return
		}
	}
}

func (f *Filtering) handleFilteringSetRules(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "Failed to read request body: %s", err)
		return
	}

	config.UserRules = strings.Split(string(body), "\n")
	onConfigModified()
	enableFilters(true)
}

func (f *Filtering) handleFilteringRefresh(w http.ResponseWriter, r *http.Request) {
	type reqJSON struct {
		Type string `json:"type"`
	}
	req := reqJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	filterN := getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	filterN.Refresh(0)
}

type filterJSON struct {
	ID          int64  `json:"id"`
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Name        string `json:"name"`
	RulesCount  uint32 `json:"rules_count"`
	LastUpdated string `json:"last_updated"`
}

func filterToJSON(f filters.Filter) filterJSON {
	fj := filterJSON{
		ID:         int64(f.ID),
		Enabled:    f.Enabled,
		URL:        f.URL,
		Name:       f.Name,
		RulesCount: uint32(f.RuleCount),
	}

	if !f.LastUpdated.IsZero() {
		fj.LastUpdated = f.LastUpdated.Format(time.RFC3339)
	}

	return fj
}

// Get filtering configuration
func (f *Filtering) handleFilteringStatus(w http.ResponseWriter, r *http.Request) {
	type respJSON struct {
		Enabled  bool   `json:"enabled"`
		Interval uint32 `json:"interval"` // in hours

		Filters          []filterJSON `json:"filters"`
		WhitelistFilters []filterJSON `json:"whitelist_filters"`
		UserRules        []string     `json:"user_rules"`

		Proxylist []filterJSON `json:"proxy_filters"`
	}
	resp := respJSON{}

	config.Lock()
	resp.Enabled = config.DNS.FilteringEnabled
	resp.Interval = config.DNS.FiltersUpdateIntervalHours
	resp.UserRules = config.UserRules
	config.RUnlock()

	f0 := Context.filters0.List(0)
	f1 := Context.filters1.List(0)
	f2 := Context.filters2.List(0)

	for _, filt := range f0 {
		fj := filterToJSON(filt)
		resp.Filters = append(resp.Filters, fj)
	}
	for _, filt := range f1 {
		fj := filterToJSON(filt)
		resp.WhitelistFilters = append(resp.WhitelistFilters, fj)
	}
	for _, filt := range f2 {
		fj := filterToJSON(filt)
		resp.Proxylist = append(resp.Proxylist, fj)
	}

	jsonVal, err := json.Marshal(resp)
	if err != nil {
		httpError2(r, w, http.StatusInternalServerError, "json encode: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(jsonVal)
}

// Set filtering configuration
func (f *Filtering) handleFilteringConfig(w http.ResponseWriter, r *http.Request) {
	type reqJSON struct {
		Enabled  bool   `json:"enabled"`
		Interval uint32 `json:"interval"`
	}
	req := reqJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}
	if !checkFiltersUpdateIntervalHours(req.Interval) {
		httpError2(r, w, http.StatusBadRequest, "Unsupported interval")
		return
	}

	config.DNS.FilteringEnabled = req.Enabled
	config.DNS.FiltersUpdateIntervalHours = req.Interval

	c := filters.Conf{}
	c.UpdateIntervalHours = req.Interval
	Context.filters0.SetConfig(c)
	Context.filters1.SetConfig(c)

	onConfigModified()

	enableFilters(true)
}

type checkHostResp struct {
	Reason   string `json:"reason"`
	FilterID int64  `json:"filter_id"`
	Rule     string `json:"rule"`

	// for FilteredBlockedService:
	SvcName string `json:"service_name"`

	// for ReasonRewrite:
	CanonName string   `json:"cname"`    // CNAME value
	IPList    []net.IP `json:"ip_addrs"` // list of IP addresses
}

func (f *Filtering) handleCheckHost(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("name")

	setts := Context.dnsFilter.GetConfig()
	setts.FilteringEnabled = true
	Context.dnsFilter.ApplyBlockedServices(&setts, nil, true)
	result, err := Context.dnsFilter.CheckHost(host, dns.TypeA, &setts)
	if err != nil {
		httpError2(r, w, http.StatusInternalServerError, "couldn't apply filtering: %s: %s", host, err)
		return
	}

	resp := checkHostResp{}
	resp.Reason = result.Reason.String()
	resp.FilterID = result.FilterID
	resp.Rule = result.Rule
	resp.SvcName = result.ServiceName
	resp.CanonName = result.CanonName
	resp.IPList = result.IPList
	js, err := json.Marshal(resp)
	if err != nil {
		httpError2(r, w, http.StatusInternalServerError, "json encode: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
}

// RegisterFilteringHandlers - register handlers
func (f *Filtering) RegisterFilteringHandlers() {
	httpRegister("GET", "/control/filtering/status", f.handleFilteringStatus)
	httpRegister("POST", "/control/filtering/config", f.handleFilteringConfig)
	httpRegister("POST", "/control/filtering/add_url", f.handleFilterAdd)
	httpRegister("POST", "/control/filtering/remove_url", f.handleFilterRemove)
	httpRegister("POST", "/control/filtering/set_url", f.handleFilterModify)
	httpRegister("POST", "/control/filtering/refresh", f.handleFilteringRefresh)
	httpRegister("POST", "/control/filtering/set_rules", f.handleFilteringSetRules)
	httpRegister("GET", "/control/filtering/check_host", f.handleCheckHost)
}

func checkFiltersUpdateIntervalHours(i uint32) bool {
	return i == 0 || i == 1 || i == 12 || i == 1*24 || i == 3*24 || i == 7*24
}
