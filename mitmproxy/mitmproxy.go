package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/file"
	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/urlfilter/proxy"
)

// MITMProxy - MITM proxy structure
type MITMProxy struct {
	proxy    *proxy.Server
	conf     Config
	confLock sync.Mutex
}

// Config - module configuration
type Config struct {
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_address"`
	UserName   string `yaml:"auth_username"`
	Password   string `yaml:"auth_password"`

	FilterDir string   `yaml:"-"`
	Filters   []filter `yaml:"proxy_filters"`

	// TLS:
	HTTPSHostname string `yaml:"-"`
	TLSCertData   []byte `yaml:"-"`
	TLSKeyData    []byte `yaml:"-"`

	HTTPClient *http.Client

	// Called when the configuration is changed by HTTP request
	ConfigModified func() `yaml:"-"`

	// Register an HTTP handler
	HTTPRegister func(string, string, func(http.ResponseWriter, *http.Request)) `yaml:"-"`
}

type filter struct {
	ID          uint64    `yaml:"-"`
	Enabled     bool      `yaml:"enabled"`
	Name        string    `yaml:"name"`
	URL         string    `yaml:"url"`
	RuleCount   uint64    `yaml:"-"`
	LastUpdated time.Time `yaml:"-"`
}

func (p *MITMProxy) filterPath(f filter) string {
	return filepath.Join(p.conf.FilterDir, fmt.Sprintf("%d.txt", f.ID))
}

func (p *MITMProxy) nextFilterID() uint64 {
	return uint64(time.Now().Unix())
}

func download(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		err := fmt.Errorf("status code: %d", resp.StatusCode)
		return nil, err
	}

	return ioutil.ReadAll(resp.Body)
}

func parseFilter(f *filter, body []byte) error {
	// f.RuleCount=
	return nil
}

func (p *MITMProxy) downloadFilter(f *filter) error {
	log.Debug("MITM: Downloading filter from %s", f.URL)

	body, err := download(p.conf.HTTPClient, f.URL)
	if err != nil {
		err := fmt.Errorf("MITM: Couldn't download filter from %s: %s", f.URL, err)
		return err
	}

	err = parseFilter(f, body)
	if err != nil {
		return err
	}
	err = file.SafeWrite()
	if err != nil {
		return err
	}
	// f.LastUpdated=
	return nil
}

func (p *MITMProxy) addFilter(nf filter) error {
	for _, f := range p.conf.Filters {
		if f.Name == nf.Name || f.URL == nf.URL {
			return fmt.Errorf("filter with this Name or URL already exists")
		}
	}

	nf.ID = p.nextFilterID()
	nf.Enabled = true
	err := p.downloadFilter(&nf)
	if err != nil {
		log.Debug("%s", err)
		return err
	}
	p.conf.Filters = append(p.conf.Filters, nf)
	return nil
}

func (p *MITMProxy) deleteFilter(url string) bool {
	nf := []filter{}
	found := false
	for _, f := range p.conf.Filters {
		if f.URL == url {
			found = true
			continue
		}
		nf = append(nf, f)
	}
	if !found {
		return false
	}
	p.conf.Filters = nf
	return true
}

// New - create a new instance of the query log
func New(conf Config) *MITMProxy {
	p := MITMProxy{}
	p.conf = conf
	err := p.create()
	if err != nil {
		log.Error("%s", err)
		return nil
	}
	if p.conf.HTTPRegister != nil {
		p.initWeb()
	}
	return &p
}

// Close - close the object
func (p *MITMProxy) Close() {
	if p.proxy != nil {
		p.proxy.Close()
		p.proxy = nil
		log.Debug("MITM: Closed proxy")
	}
}

// WriteDiskConfig - write configuration on disk
func (p *MITMProxy) WriteDiskConfig(c *Config) {
	p.confLock.Lock()
	*c = p.conf
	p.confLock.Unlock()
}

// Start - start proxy server
func (p *MITMProxy) Start() error {
	if !p.conf.Enabled {
		return nil
	}
	err := p.proxy.Start()
	if err != nil {
		return err
	}
	log.Debug("MITM: Running...")
	return nil
}

// Create a gomitmproxy object
func (p *MITMProxy) create() error {
	if !p.conf.Enabled {
		return nil
	}

	c := proxy.Config{}
	addr, port, err := net.SplitHostPort(p.conf.ListenAddr)
	if err != nil {
		return fmt.Errorf("net.SplitHostPort: %s", err)
	}

	c.CompressContentScript = true
	c.ProxyConfig.ListenAddr = &net.TCPAddr{}
	c.ProxyConfig.ListenAddr.IP = net.ParseIP(addr)
	if c.ProxyConfig.ListenAddr.IP == nil {
		return fmt.Errorf("Invalid IP: %s", addr)
	}
	c.ProxyConfig.ListenAddr.Port, err = strconv.Atoi(port)
	if c.ProxyConfig.ListenAddr.Port < 0 || c.ProxyConfig.ListenAddr.Port > 0xffff || err != nil {
		return fmt.Errorf("Invalid port number: %s", port)
	}

	c.ProxyConfig.Username = p.conf.UserName
	c.ProxyConfig.Password = p.conf.Password

	if len(p.conf.TLSCertData) != 0 {
		err := p.prepareTLSConf(&c.ProxyConfig)
		if err != nil {
			return err
		}
	}
	// c.ProxyConfig.APIHost

	for i, f := range p.conf.Filters {
		if !f.Enabled {
			continue
		}
		c.FiltersPaths[i] = p.filterPath(f)
	}

	p.proxy, err = proxy.NewServer(c)
	if err != nil {
		return fmt.Errorf("proxy.NewServer: %s", err)
	}
	return nil
}

func (p *MITMProxy) prepareTLSConf(pc *gomitmproxy.Config) error {
	tlsCert, err := tls.X509KeyPair(p.conf.TLSCertData, p.conf.TLSKeyData)
	if err != nil {
		return fmt.Errorf("failed to load root CA: %v", err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid certificate: %v", err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		return fmt.Errorf("failed to create MITM config: %v", err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("AdGuard")      // cert organization
	cert, err := mitmConfig.GetOrCreateCert(p.conf.HTTPSHostname)
	if err != nil {
		return fmt.Errorf("failed to generate HTTPS proxy certificate for %s: %v", p.conf.HTTPSHostname, err)
	}

	pc.TLSConfig.Certificates = []tls.Certificate{*cert}
	pc.TLSConfig.ServerName = p.conf.HTTPSHostname
	pc.MITMConfig = mitmConfig
	// pc.MITMExceptions
	return nil
}

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

func (p *MITMProxy) initWeb() {
	p.conf.HTTPRegister("GET", "/control/proxy_info", p.handleGetConfig)
	p.conf.HTTPRegister("POST", "/control/proxy_config", p.handleSetConfig)

	p.conf.HTTPRegister("GET", "/control/proxy_filter/status", p.handleFilterStatus)
	p.conf.HTTPRegister("POST", "/control/proxy_filter/add", p.handleFilterAdd)
	p.conf.HTTPRegister("POST", "/control/proxy_filter/remove", p.handleFilterRemove)
}
