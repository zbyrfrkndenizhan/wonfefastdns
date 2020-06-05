package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/file"
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
	Enabled    bool   `yaml:"enabled"`
	ListenAddr string `yaml:"listen_address"`

	UserName string `yaml:"auth_username"`
	Password string `yaml:"auth_password"`

	FilterDir string   `yaml:"-"`
	Filters   []filter `yaml:"proxy_filters"`

	// TLS:
	RegenCert    bool   `yaml:"regenerate_cert"` // Regenerate certificate on cert loading failure
	CertDir      string `yaml:"-"`               // Directory where Root certificate & pkey is stored
	certFileName string
	pkeyFileName string
	certData     []byte
	pkeyData     []byte

	HTTPClient *http.Client `yaml:"-"`

	// Called when the configuration is changed by HTTP request
	ConfigModified func() `yaml:"-"`

	// Register an HTTP handler
	HTTPRegister func(string, string, func(http.ResponseWriter, *http.Request)) `yaml:"-"`
}

// New - create a new instance of the query log
func New(conf Config) *MITMProxy {
	p := MITMProxy{}

	p.conf = conf
	p.conf.certFileName = filepath.Join(p.conf.CertDir, "/http_proxy.crt")
	p.conf.pkeyFileName = filepath.Join(p.conf.CertDir, "/http_proxy.key")

	p.initFilters()

	err := p.create()
	if err != nil {
		log.Error("MITM: %s", err)
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

// Duplicate filter array
func arrayFilterDup(f []filter) []filter {
	nf := make([]filter, len(f))
	copy(nf, f)
	return nf
}

// WriteDiskConfig - write configuration on disk
func (p *MITMProxy) WriteDiskConfig(c *Config) {
	p.confLock.Lock()
	*c = p.conf
	c.Filters = arrayFilterDup(p.conf.Filters)
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
	c.ProxyConfig.APIHost = "adguardhome.api"
	addr, port, err := net.SplitHostPort(p.conf.ListenAddr)
	if err != nil {
		return fmt.Errorf("net.SplitHostPort: %s", err)
	}

	c.CompressContentScript = true
	c.ProxyConfig.ListenAddr = &net.TCPAddr{}
	c.ProxyConfig.ListenAddr.IP = net.ParseIP(addr)
	if c.ProxyConfig.ListenAddr.IP == nil {
		return fmt.Errorf("invalid IP: %s", addr)
	}
	c.ProxyConfig.ListenAddr.Port, err = strconv.Atoi(port)
	if c.ProxyConfig.ListenAddr.Port < 0 || c.ProxyConfig.ListenAddr.Port > 0xffff || err != nil {
		return fmt.Errorf("invalid port number: %s", port)
	}

	c.ProxyConfig.Username = p.conf.UserName
	c.ProxyConfig.Password = p.conf.Password

	err = p.loadCert()
	if err != nil {
		if !p.conf.RegenCert {
			return err
		}
		log.Debug("%s", err)

		// certificate or private key file doesn't exist - generate new
		err = p.createRootCert()
		if err != nil {
			return err
		}
	}

	c.ProxyConfig.MITMConfig, err = p.prepareMITMConfig()
	if err != nil {
		if !p.conf.RegenCert {
			return err
		}

		// certificate or private key is invalid - generate new
		err = p.createRootCert()
		if err != nil {
			return err
		}

		c.ProxyConfig.MITMConfig, err = p.prepareMITMConfig()
		if err != nil {
			return err
		}
	}

	c.FiltersPaths = make(map[int]string)
	for i, f := range p.conf.Filters {
		if !f.Enabled &&
			f.RuleCount != 0 { // loaded
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

// Load cert and pkey from file
func (p *MITMProxy) loadCert() error {
	var err error
	p.conf.certData, err = ioutil.ReadFile(p.conf.certFileName)
	if err != nil {
		return err
	}
	p.conf.pkeyData, err = ioutil.ReadFile(p.conf.pkeyFileName)
	if err != nil {
		return err
	}
	return nil
}

// Create Root certificate and pkey and store it on disk
func (p *MITMProxy) createRootCert() error {
	cert, key, err := mitm.NewAuthority("AdGuardHome Root", "AdGuard", 365*24*time.Hour)
	if err != nil {
		return err
	}

	p.conf.certData = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	p.conf.pkeyData = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	log.Debug("MITM: Created root certificate and key")

	err = p.storeCert(p.conf.certData, p.conf.pkeyData)
	if err != nil {
		return err
	}
	return nil
}

// Store cert & pkey on disk
func (p *MITMProxy) storeCert(certData []byte, pkeyData []byte) error {
	err := file.SafeWrite(p.conf.certFileName, certData)
	if err != nil {
		return err
	}

	err = file.SafeWrite(p.conf.pkeyFileName, pkeyData)
	if err != nil {
		return err
	}

	log.Debug("MITM: stored root certificate and key: %s, %s", p.conf.certFileName, p.conf.pkeyFileName)
	return nil
}

// Fill TLSConfig & MITMConfig objects
func (p *MITMProxy) prepareMITMConfig() (*mitm.Config, error) {
	tlsCert, err := tls.X509KeyPair(p.conf.certData, p.conf.pkeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to load root CA: %v", err)
	}
	privateKey := tlsCert.PrivateKey.(*rsa.PrivateKey)

	x509c, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("invalid certificate: %v", err)
	}

	mitmConfig, err := mitm.NewConfig(x509c, privateKey, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create MITM config: %v", err)
	}

	mitmConfig.SetValidity(time.Hour * 24 * 7) // generate certs valid for 7 days
	mitmConfig.SetOrganization("AdGuard")      // cert organization
	return mitmConfig, nil
}
