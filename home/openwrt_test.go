package home

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReadConf(t *testing.T) {
	oc := openwrtConfig{}
	data := []byte(`		config interface 'lan'
option netmask '255.255.255.0'
option ipaddr '192.168.8.1'`)
	oc.readConf(data, "interface", "lan")
	assert.Equal(t, "255.255.255.0", oc.netmask)
	assert.Equal(t, "192.168.8.1", oc.ipaddr)

	data = []byte(`		config dhcp 'unknown'

config dhcp 'lan'
option start '100'
option limit '150'
option leasetime '12h'

config dhcp 'unknown'`)
	oc.readConf(data, "dhcp", "lan")
	assert.Equal(t, "100", oc.dhcpStart)
	assert.Equal(t, "150", oc.dhcpLimit)
	assert.Equal(t, "12h", oc.dhcpLeasetime)

	data = []byte(`		# comment
nameserver abab::1234

nameserver 1.2.3.4`)
	oc.readResolvConf(data)
	assert.Equal(t, "abab::1234", oc.nameservers[0])
	assert.Equal(t, "1.2.3.4", oc.nameservers[1])

	err := oc.prepareOutput()
	assert.Equal(t, nil, err)
	assert.Equal(t, "br-lan", oc.iface)
	assert.Equal(t, "192.168.8.1", oc.gwIP)
	assert.Equal(t, "255.255.255.0", oc.snMask)
	assert.Equal(t, "192.168.8.100", oc.rangeStart)
	assert.Equal(t, "192.168.8.249", oc.rangeEnd)
	assert.Equal(t, uint32(43200), oc.leaseDur)
	assert.Equal(t, "abab::1234", oc.bsDNS[0])
	assert.Equal(t, "1.2.3.4", oc.bsDNS[1])

	data = []byte(`config host '123412341234'
option mac '12:34:12:34:12:34'
option ip '192.168.8.2'
option name 'hostname'`)
	assert.True(t, nil == oc.readConfDHCPStatic(data))
	assert.Equal(t, 1, len(oc.leases))
	assert.Equal(t, "12:34:12:34:12:34", oc.leases[0].HWAddr.String())
	assert.Equal(t, "192.168.8.2", oc.leases[0].IP.String())
	assert.Equal(t, "hostname", oc.leases[0].Hostname)

}
