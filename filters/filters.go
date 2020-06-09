package filters

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/file"
	"github.com/AdguardTeam/golibs/log"
)

// filter storage object
type filterStg struct {
	updateTaskRunning bool
	updated           []Filter
	conf              Conf
	confLock          sync.Mutex

	Users []EventHandler
}

// initialize the module
func newFiltersObj(conf Conf) Filters {
	fs := filterStg{}
	fs.conf = conf
	return &fs
}

// Start - start module
func (fs *filterStg) Start() {
	for i := range fs.conf.Proxylist {
		f := &fs.conf.Proxylist[i]
		fname := fs.filePath(*f)
		st, err := os.Stat(fname)
		if err != nil {
			log.Error("filterStg: os.Stat: %s %s", fname, err)
			continue
		}
		f.LastUpdated = st.ModTime()
		f.nextUpdate = f.LastUpdated.Add(time.Duration(fs.conf.UpdateIntervalHours) * time.Hour)

		body, err := ioutil.ReadFile(fname)
		if err != nil {
			log.Error("filterStg: ioutil.ReadFile: %s %s", fname, err)
			continue
		}
		_ = parseFilter(f, body)
	}

	if !fs.updateTaskRunning {
		fs.updateTaskRunning = true
		go fs.updateFilters()
	}
}

// Close - close the module
func (fs *filterStg) Close() {
}

// Duplicate filter array
func arrayFilterDup(f []Filter) []Filter {
	nf := make([]Filter, len(f))
	copy(nf, f)
	return nf
}

// WriteDiskConfig - write configuration on disk
func (fs *filterStg) WriteDiskConfig(c *Conf) {
	fs.confLock.Lock()
	*c = fs.conf
	c.Proxylist = arrayFilterDup(fs.conf.Proxylist)
	fs.confLock.Unlock()
}

// AddUser - add user handler for notifications
func (fs *filterStg) AddUser(handler EventHandler) {
	fs.Users = append(fs.Users, handler)
}

// notify all users about the event
func (fs *filterStg) notifyUsers(flags uint) {
	for _, u := range fs.Users {
		u(flags)
	}
}

// List (thread safe)
func (fs *filterStg) List(flags uint) []Filter {
	fs.confLock.Lock()
	ff := make([]Filter, len(fs.conf.Proxylist))
	for _, f := range fs.conf.Proxylist {
		nf := f
		nf.Path = fs.filePath(f)
		ff = append(ff, nf)
	}
	fs.confLock.Unlock()
	return ff
}

// Get filter file name
func (fs *filterStg) filePath(f Filter) string {
	return filepath.Join(fs.conf.FilterDir, fmt.Sprintf("%d.txt", f.ID))
}

// Get next filter ID
func (fs *filterStg) nextFilterID() uint64 {
	return uint64(time.Now().Unix())
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
func parseFilter(f *Filter, body []byte) error {
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
func (fs *filterStg) downloadFilter(f *Filter) error {
	log.Debug("filterStg: Downloading filter from %s", f.URL)

	body, err := download(fs.conf.HTTPClient, f.URL)
	if err != nil {
		err := fmt.Errorf("filterStg: Couldn't download filter from %s: %s", f.URL, err)
		return err
	}

	err = parseFilter(f, body)
	if err != nil {
		return err
	}

	fname := fs.filePath(*f)
	err = file.SafeWrite(fname, body)
	if err != nil {
		return err
	}

	log.Debug("filterStg: saved filter %s at %s", f.URL, fname)
	f.LastUpdated = time.Now()
	return nil
}

// Add - add filter (thread safe)
func (fs *filterStg) Add(nf Filter) error {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	for _, f := range fs.conf.Proxylist {
		if f.Name == nf.Name || f.URL == nf.URL {
			return fmt.Errorf("filter with this Name or URL already exists")
		}
	}

	nf.ID = fs.nextFilterID()
	nf.Enabled = true
	err := fs.downloadFilter(&nf)
	if err != nil {
		log.Debug("%s", err)
		return err
	}
	fs.conf.Proxylist = append(fs.conf.Proxylist, nf)
	log.Debug("filterStg: added filter %s", nf.URL)
	return nil
}

// Delete - remove filter (thread safe)
func (fs *filterStg) Delete(url string) *Filter {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	nf := []Filter{}
	var found *Filter
	for _, f := range fs.conf.Proxylist {
		if f.URL == url {
			found = &f
			continue
		}
		nf = append(nf, f)
	}
	if found == nil {
		return nil
	}
	fs.conf.Proxylist = nf
	log.Debug("filterStg: removed filter %s", url)
	found.Path = fs.filePath(*found) // the caller will delete the file
	return found
}

// Modify - set filter properties (thread safe)
// Return Status* bitarray
func (fs *filterStg) Modify(url string, enabled bool, name string, newURL string) int {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	st := 0

	for _, f := range fs.conf.Proxylist {
		if f.URL == url {

			f.Name = name

			if f.Enabled != enabled {
				f.Enabled = enabled
				st |= StatusChangedEnabled
			}

			if f.URL != newURL {
				f.URL = newURL
				st |= StatusChangedURL
			}

			break
		}
	}

	if st == 0 {
		return StatusNotFound
	}

	return st
}

// Refresh - begin filters update procedure
func (fs *filterStg) Refresh(flags uint) {
	for i := range fs.conf.Proxylist {
		f := &fs.conf.Proxylist[i]
		f.nextUpdate = time.Time{}
	}
}

// Periodically update filters
// Algorithm:
// . Get next filter to update:
//  . Download data from Internet and store on disk (in a new file)
//  . Update filter's properties
//  . Repeat for next filter
// (All filters are downloaded)
// . Stop modules that use filters
// . Rename "new file name" -> "old file name"
// . Restart modules that use filters
func (fs *filterStg) updateFilters() {
	period := time.Hour
	for {
		// if !dns.isRunning()
		//  sleep

		var uf Filter
		fs.confLock.Lock()
		f := fs.getNextToUpdate()
		if f != nil {
			uf = *f
		}
		fs.confLock.Unlock()

		if f == nil {
			fs.applyUpdate()

			time.Sleep(period)
			continue
		}

		uf.ID = fs.nextFilterID()
		err := fs.downloadFilter(&uf)
		if err != nil {
			continue
		}

		// add new filter to the list
		fs.updated = append(fs.updated, uf)
	}
}

// Get next filter to update
func (fs *filterStg) getNextToUpdate() *Filter {
	now := time.Now()

	for i := range fs.conf.Proxylist {
		f := &fs.conf.Proxylist[i]

		if f.Enabled &&
			f.nextUpdate.Unix() <= now.Unix() {

			f.nextUpdate = now.Add(time.Duration(fs.conf.UpdateIntervalHours) * time.Hour)
			return f
		}
	}

	return nil
}

// Replace filter files
func (fs *filterStg) applyUpdate() {
	if len(fs.updated) == 0 {
		log.Debug("filterStg: no filters were updated")
		return
	}

	fs.notifyUsers(EventBeforeUpdate)

	nUpdated := 0

	fs.confLock.Lock()
	for _, uf := range fs.updated {
		found := false

		for i := range fs.conf.Proxylist {
			f := &fs.conf.Proxylist[i]

			if uf.URL == f.URL {
				name := fs.filePath(*f)
				updatedName := fs.filePath(uf)
				err := os.Rename(updatedName, name)
				if err != nil {
					log.Error("filterStg: os.Rename:%s", err)
				}
				f.RuleCount = uf.RuleCount
				f.LastUpdated = uf.LastUpdated
				nUpdated++
				found = true
				break
			}
		}

		if !found {
			_ = os.Remove(fs.filePath(uf))
		}
	}
	fs.confLock.Unlock()

	log.Debug("filterStg: %d filters were updated", nUpdated)

	fs.updated = nil
	fs.notifyUsers(EventAfterUpdate)
}
