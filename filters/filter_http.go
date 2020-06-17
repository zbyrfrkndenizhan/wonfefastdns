package filters

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
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

func (f *Filtering) getFilterModule(t string) Filters {
	switch t {
	case "blocklist":
		return f.dnsBlocklist

	case "whitelist":
		return f.dnsAllowlist

	case "proxylist":
		return f.Proxylist

	default:
		return nil
	}
}

func (f *Filtering) restartMods(t string) {
	fN := f.getFilterModule(t)
	fN.NotifyObserver(EventBeforeUpdate)
	fN.NotifyObserver(EventAfterUpdate)
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

	filterN := f.getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	filt := Filter{
		Enabled: true,
		Name:    req.Name,
		URL:     req.URL,
	}
	err = filterN.Add(filt)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "add filter: %s", err)
		return
	}

	f.conf.ConfigModified()

	f.restartMods(req.Type)
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

	filterN := f.getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	removed := filterN.Delete(req.URL)
	if removed == nil {
		httpError2(r, w, http.StatusInternalServerError, "no filter with such URL")
		return
	}

	f.conf.ConfigModified()

	if removed.Enabled {
		f.restartMods(req.Type)
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

	filterN := f.getFilterModule(req.Type)
	if filterN == nil {
		httpError2(r, w, http.StatusBadRequest, "invalid type: %s", req.Type)
		return
	}

	st, _, err := filterN.Modify(req.URL, req.Data.Enabled, req.Data.Name, req.Data.URL)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "%s", err)
		return
	}

	f.conf.ConfigModified()

	if st == StatusChangedEnabled ||
		st == StatusChangedURL {

		// TODO StatusChangedURL: delete old file

		f.restartMods(req.Type)
	}
}

func (f *Filtering) handleFilteringSetRules(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError2(r, w, http.StatusBadRequest, "Failed to read request body: %s", err)
		return
	}

	f.conf.UserRules = strings.Split(string(body), "\n")
	f.conf.ConfigModified()
	f.restartMods("blocklist")
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

	filterN := f.getFilterModule(req.Type)
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

func filterToJSON(f Filter) filterJSON {
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

	resp.Enabled = f.conf.Enabled
	resp.Interval = f.conf.UpdateIntervalHours
	resp.UserRules = f.conf.UserRules

	f0 := f.dnsBlocklist.List(0)
	f1 := f.dnsAllowlist.List(0)
	f2 := f.Proxylist.List(0)

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
	if !CheckFiltersUpdateIntervalHours(req.Interval) {
		httpError2(r, w, http.StatusBadRequest, "Unsupported interval")
		return
	}

	restart := false
	if f.conf.Enabled != req.Enabled {
		restart = true
	}
	f.conf.Enabled = req.Enabled
	f.conf.UpdateIntervalHours = req.Interval

	c := Conf{}
	c.UpdateIntervalHours = req.Interval
	f.dnsBlocklist.SetConfig(c)
	f.dnsAllowlist.SetConfig(c)
	f.Proxylist.SetConfig(c)

	f.conf.ConfigModified()

	if restart {
		f.restartMods("blocklist")
	}
}

// registerWebHandlers - register handlers
func (f *Filtering) registerWebHandlers() {
	f.conf.HTTPRegister("GET", "/control/filtering/status", f.handleFilteringStatus)
	f.conf.HTTPRegister("POST", "/control/filtering/config", f.handleFilteringConfig)
	f.conf.HTTPRegister("POST", "/control/filtering/add_url", f.handleFilterAdd)
	f.conf.HTTPRegister("POST", "/control/filtering/remove_url", f.handleFilterRemove)
	f.conf.HTTPRegister("POST", "/control/filtering/set_url", f.handleFilterModify)
	f.conf.HTTPRegister("POST", "/control/filtering/refresh", f.handleFilteringRefresh)
	f.conf.HTTPRegister("POST", "/control/filtering/set_rules", f.handleFilteringSetRules)
}

// CheckFiltersUpdateIntervalHours - verify update interval
func CheckFiltersUpdateIntervalHours(i uint32) bool {
	return i == 0 || i == 1 || i == 12 || i == 1*24 || i == 3*24 || i == 7*24
}
