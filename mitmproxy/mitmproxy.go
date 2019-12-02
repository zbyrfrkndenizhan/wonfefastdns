package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/gomitmproxy/mitm"
	"github.com/AdguardTeam/urlfilter/proxy"
)

// MITMProxy - MITM proxy structure
type MITMProxy struct {
	proxy *proxy.Server
	conf  Config
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
	if !p.create() {
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
	return p.proxy.Start()
}

// Create a gomitmproxy object
func (p *MITMProxy) create() bool {
	if !p.conf.Enabled {
		return true
	}

	c := proxy.Config{}
	addr, port, err := net.SplitHostPort(p.conf.ListenAddr)
	if err != nil {
		log.Error("net.SplitHostPort: %s", err)
		return false
	}

	c.CompressContentScript = true
	c.ProxyConfig.ListenAddr = &net.TCPAddr{}
	c.ProxyConfig.ListenAddr.IP = net.ParseIP(addr)
	if c.ProxyConfig.ListenAddr.IP == nil {
		log.Error("Invalid IP: %s", addr)
		return false
	}
	c.ProxyConfig.ListenAddr.Port, err = strconv.Atoi(port)
	if c.ProxyConfig.ListenAddr.IP == nil {
		log.Error("Invalid port number: %s", port)
		return false
	}

	c.ProxyConfig.Username = p.conf.UserName
	c.ProxyConfig.Password = p.conf.Password

	if p.conf.TLSCertPath != "" {
		tlsCert, err := tls.LoadX509KeyPair(p.conf.TLSCertPath, p.conf.TLSKeyPath)
		if err != nil {
			log.Fatalf("failed to load root CA: %v", err)
		}
		privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

		x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
		if err != nil {
			log.Fatalf("invalid certificate: %v", err)
		}
		mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
		if err != nil {
			log.Fatalf("failed to create MITM config: %v", err)
		}
		mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
		mitmConfig.SetOrganization("AdGuard")      // cert organization
		cert, err := mitmConfig.GetOrCreateCert(p.conf.HTTPSHostname)
		if err != nil {
			log.Fatalf("failed to generate HTTPS proxy certificate for %s: %v", p.conf.HTTPSHostname, err)
		}
		c.ProxyConfig.TLSConfig.Certificates = []tls.Certificate{*cert}
		c.ProxyConfig.TLSConfig.ServerName = p.conf.HTTPSHostname
		c.ProxyConfig.MITMConfig = mitmConfig
		// c.ProxyConfig.MITMExceptions
	}
	// c.ProxyConfig.APIHost

	p.proxy, err = proxy.NewServer(c)
	if err != nil {
		log.Error("proxy.NewServer: %s", err)
		return false
	}
	return true
}
