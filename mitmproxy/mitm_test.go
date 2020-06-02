package mitmproxy

import (
	"testing"
)

func TestMITM(t *testing.T) {
	conf := Config{}
	conf.Enabled = true
	conf.ListenAddr = "127.0.0.1:8081"
	s := New(conf)
	s.Start()
	s.Close()
}
