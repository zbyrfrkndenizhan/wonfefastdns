package mitmproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
)

type mitmConfigJSON struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listen_address"`
	ListenPort int    `json:"listen_port"`
	UserName   string `json:"auth_username"`
	Password   string `json:"auth_password"`
}

func httpError(r *http.Request, w http.ResponseWriter, code int, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	log.Info("MITM: %s %s: %s", r.Method, r.URL, text)
	http.Error(w, text, code)
}

func (p *MITMProxy) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	resp := mitmConfigJSON{}
	p.confLock.Lock()
	resp.Enabled = p.conf.Enabled
	host, port, _ := net.SplitHostPort(p.conf.ListenAddr)
	resp.ListenAddr = host
	resp.ListenPort, _ = strconv.Atoi(port)
	resp.UserName = p.conf.UserName
	resp.Password = p.conf.Password
	p.confLock.Unlock()

	js, err := json.Marshal(resp)
	if err != nil {
		httpError(r, w, http.StatusInternalServerError, "json.Marshal: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
}

func (p *MITMProxy) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	req := mitmConfigJSON{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}
	p.confLock.Lock()
	p.conf.Enabled = req.Enabled
	p.conf.ListenAddr = net.JoinHostPort(req.ListenAddr, strconv.Itoa(req.ListenPort))
	p.conf.UserName = req.UserName
	p.conf.Password = req.Password
	p.confLock.Unlock()
	p.conf.ConfigModified()

	p.Close()
	err = p.create()
	if err != nil {
		httpError(r, w, http.StatusInternalServerError, "%s", err)
		return
	}
}

func (p *MITMProxy) handleFilterStatus(w http.ResponseWriter, r *http.Request) {
	type filterJSON struct {
		Enabled     bool      `json:"enabled"`
		Name        string    `json:"name"`
		URL         string    `json:"url"`
		RuleCount   uint64    `json:"rules_count"`
		LastUpdated time.Time `json:"last_updated"`
	}
	type Resp struct {
		Filters []filterJSON `json:"filters"`
	}
	resp := Resp{}

	p.confLock.Lock()
	for _, f := range p.conf.Filters {
		fj := filterJSON{
			Enabled:     f.Enabled,
			Name:        f.Name,
			URL:         f.URL,
			RuleCount:   f.RuleCount,
			LastUpdated: f.LastUpdated,
		}
		resp.Filters = append(resp.Filters, fj)
	}
	p.confLock.Unlock()

	js, err := json.Marshal(resp)
	if err != nil {
		httpError(r, w, http.StatusInternalServerError, "json.Marshal: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(js)
}

func (p *MITMProxy) handleFilterAdd(w http.ResponseWriter, r *http.Request) {
	type Req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	req := Req{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	f := filter{
		Name: req.Name,
		URL:  req.URL,
	}
	p.confLock.Lock()
	err = p.addFilter(f)
	p.confLock.Unlock()
	if err != nil {
		httpError(r, w, http.StatusBadRequest, "addFilter: %s", err)
		return
	}

	p.conf.ConfigModified()
}

func (p *MITMProxy) handleFilterRemove(w http.ResponseWriter, r *http.Request) {
	type Req struct {
		URL string `json:"url"`
	}
	req := Req{}
	_, err := jsonutil.DecodeObject(&req, r.Body)
	if err != nil {
		httpError(r, w, http.StatusBadRequest, "json.Decode: %s", err)
		return
	}

	p.confLock.Lock()
	result := p.deleteFilter(req.URL)
	p.confLock.Unlock()
	if !result {
		httpError(r, w, http.StatusInternalServerError, "No filter with such URL")
		return
	}

	p.conf.ConfigModified()
}

// Initialize web handlers
func (p *MITMProxy) initWeb() {
	p.conf.HTTPRegister("GET", "/control/proxy_info", p.handleGetConfig)
	p.conf.HTTPRegister("POST", "/control/proxy_config", p.handleSetConfig)

	p.conf.HTTPRegister("GET", "/control/proxy_filter/status", p.handleFilterStatus)
	p.conf.HTTPRegister("POST", "/control/proxy_filter/add", p.handleFilterAdd)
	p.conf.HTTPRegister("POST", "/control/proxy_filter/remove", p.handleFilterRemove)
}
