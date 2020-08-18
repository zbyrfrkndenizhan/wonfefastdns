package mitmproxy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
)

// Print to log and set HTTP error message
func httpError(r *http.Request, w http.ResponseWriter, code int, format string, args ...interface{}) {
	text := fmt.Sprintf(format, args...)
	log.Info("MITM: %s %s: %s", r.Method, r.URL, text)
	http.Error(w, text, code)
}

type mitmConfigJSON struct {
	Enabled    bool   `json:"enabled"`
	ListenAddr string `json:"listen_address"`
	ListenPort int    `json:"listen_port"`

	UserName string `json:"auth_username"`
	Password string `json:"auth_password"`

	CertData string `json:"cert_data"`
	PKeyData string `json:"pkey_data"`
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

	if !((len(req.CertData) != 0 && len(req.PKeyData) != 0) ||
		(len(req.CertData) == 0 && len(req.PKeyData) == 0)) {
		httpError(r, w, http.StatusBadRequest, "certificate & private key must be both empty or specified")
		return
	}

	p.confLock.Lock()
	if len(req.CertData) != 0 {
		err = p.storeCert([]byte(req.CertData), []byte(req.PKeyData))
		if err != nil {
			httpError(r, w, http.StatusInternalServerError, "%s", err)
			p.confLock.Unlock()
			return
		}
		p.conf.RegenCert = false
	} else {
		p.conf.RegenCert = true
	}
	p.conf.Enabled = req.Enabled
	p.conf.ListenAddr = net.JoinHostPort(req.ListenAddr, strconv.Itoa(req.ListenPort))
	p.conf.UserName = req.UserName
	p.conf.Password = req.Password
	p.confLock.Unlock()

	p.conf.ConfigModified()

	p.Close()
	err = p.Restart()
	if err != nil {
		httpError(r, w, http.StatusInternalServerError, "%s", err)
		return
	}
}

// Initialize web handlers
func (p *MITMProxy) initWeb() {
	p.conf.HTTPRegister("GET", "/control/proxy_info", p.handleGetConfig)
	p.conf.HTTPRegister("POST", "/control/proxy_config", p.handleSetConfig)
}
