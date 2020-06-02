package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

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

// Fill TLSConfig & MITMConfig objects
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
