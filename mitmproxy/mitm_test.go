package mitmproxy

import (
	"net/http"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func prepareTestDir() string {
	const dir = "./agh-test"
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func TestMITM(t *testing.T) {
	dir := prepareTestDir()
	defer func() { _ = os.RemoveAll(dir) }()

	conf := Config{}
	conf.Enabled = true
	conf.CertDir = dir
	conf.FilterDir = dir
	conf.RegenCert = true
	conf.ListenAddr = "127.0.0.1:8081"
	s := New(conf)
	assert.NotNil(t, s)

	err := s.Start()
	assert.Nil(t, err)

	proxyURL, _ := url.Parse("http://127.0.0.1:8081")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	c := http.Client{
		Transport: transport,
	}
	resp, err := c.Get("http://example.com/")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, err = c.Get("http://adguardhome.api/cert.crt")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	s.Close()
}
