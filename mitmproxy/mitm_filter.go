package mitmproxy

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/file"
	"github.com/AdguardTeam/golibs/log"
)

// Filter object type
type filter struct {
	ID          uint64    `yaml:"id"`
	Enabled     bool      `yaml:"enabled"`
	Name        string    `yaml:"name"`
	URL         string    `yaml:"url"`
	RuleCount   uint64    `yaml:"-"`
	LastUpdated time.Time `yaml:"-"`
}

// Get filter file name
func (p *MITMProxy) filterPath(f filter) string {
	return filepath.Join(p.conf.FilterDir, fmt.Sprintf("%d.txt", f.ID))
}

// Get next filter ID
func (p *MITMProxy) nextFilterID() uint64 {
	return uint64(time.Now().Unix())
}

func (p *MITMProxy) initFilters() {
	for i := range p.conf.Filters {
		f := &p.conf.Filters[i]
		fname := p.filterPath(*f)
		st, err := os.Stat(fname)
		if err != nil {
			log.Error("MITM: os.Stat: %s %s", fname, err)
			continue
		}
		f.LastUpdated = st.ModTime()

		body, err := ioutil.ReadFile(fname)
		if err != nil {
			log.Error("MITM: ioutil.ReadFile: %s %s", fname, err)
			continue
		}
		_ = parseFilter(f, body)
	}
}

// Download data via HTTP
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

// Parse filter data
func parseFilter(f *filter, body []byte) error {
	data := string(body)
	rulesCount := 0

	// Count lines in the filter
	for len(data) != 0 {
		line := util.SplitNext(&data, '\n')
		if len(line) == 0 ||
			line[0] == '#' ||
			line[0] == '!' {
			continue
		}

		rulesCount++
	}

	f.RuleCount = uint64(rulesCount)
	return nil
}

// Download filter data
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

	fname := p.filterPath(*f)
	err = file.SafeWrite(fname, body)
	if err != nil {
		return err
	}

	log.Debug("MITM: saved filter %s at %s", f.URL, fname)
	f.LastUpdated = time.Now()
	return nil
}

// Add filter
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

// Remove filter
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
