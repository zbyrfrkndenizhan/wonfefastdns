package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/jsonutil"
	"github.com/AdguardTeam/golibs/log"
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
	Enabled       bool   `yaml:"enabled"`
	ListenAddr    string `yaml:"listen_address"`
	UserName      string `yaml:"auth_username"`
	Password      string `yaml:"auth_password"`
	HTTPSHostname string `yaml:"https_hostname"`
	TLSCertPath   string `yaml:"tls_cert_path"`
	TLSKeyPath    string `yaml:"tls_key_path"`

	// Called when the configuration is changed by HTTP request
	ConfigModified func() `yaml:"-"`

	// Register an HTTP handler
	HTTPRegister func(string, string, func(http.ResponseWriter, *http.Request)) `yaml:"-"`
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
	*c = p.conf
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

	if p.conf.TLSCertPath != "" {
		tlsCert, err := tls.LoadX509KeyPair(p.conf.TLSCertPath, p.conf.TLSKeyPath)
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
		c.ProxyConfig.TLSConfig.Certificates = []tls.Certificate{*cert}
		c.ProxyConfig.TLSConfig.ServerName = p.conf.HTTPSHostname
		c.ProxyConfig.MITMConfig = mitmConfig
		// c.ProxyConfig.MITMExceptions
	}
	// c.ProxyConfig.APIHost

	p.proxy, err = proxy.NewServer(c)
	if err != nil {
		return fmt.Errorf("proxy.NewServer: %s", err)
	}
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

func (p *MITMProxy) initWeb() {
	p.conf.HTTPRegister("GET", "/control/proxy_info", p.handleGetConfig)
	p.conf.HTTPRegister("POST", "/control/proxy_config", p.handleSetConfig)
}
