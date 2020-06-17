package filters

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/log"
	"go.uber.org/atomic"
)

// filter storage object
type filterStg struct {
	updateTaskRunning bool
	updated           []Filter  // list of filters that were downloaded during update procedure
	updateChan        chan bool // signal for the update goroutine

	conf     *Conf
	confLock sync.Mutex
	nextID   atomic.Uint64 // next filter ID

	observer EventHandler // user function that receives notifications
}

// initialize the module
func newFiltersObj(conf Conf) Filters {
	fs := filterStg{}
	fs.conf = &Conf{}
	*fs.conf = conf
	fs.nextID.Store(uint64(time.Now().Unix()))
	fs.updateChan = make(chan bool, 2)
	return &fs
}

// Start - start module
func (fs *filterStg) Start() {
	_ = os.MkdirAll(fs.conf.FilterDir, 0755)

	// Load all enabled filters
	// On error, RuleCount is set to 0 - users won't try to use such filters
	//  and in the future the update procedure will re-download the file
	for i := range fs.conf.List {
		f := &fs.conf.List[i]

		fname := fs.filePath(*f)
		st, err := os.Stat(fname)
		if err != nil {
			log.Debug("Filters: os.Stat: %s %s", fname, err)
			continue
		}
		f.LastUpdated = st.ModTime()

		if !f.Enabled {
			continue
		}

		file, err := os.OpenFile(fname, os.O_RDONLY, 0)
		if err != nil {
			log.Error("Filters: os.OpenFile: %s %s", fname, err)
			continue
		}

		_ = parseFilter(f, file)
		file.Close()

		f.nextUpdate = f.LastUpdated.Add(time.Duration(fs.conf.UpdateIntervalHours) * time.Hour)
	}

	if !fs.updateTaskRunning {
		fs.updateTaskRunning = true
		go fs.updateBySignal()
		go fs.updateByTimer()
	}
}

// Close - close the module
func (fs *filterStg) Close() {
	fs.updateChan <- false
	close(fs.updateChan)
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
	*c = *fs.conf
	c.List = arrayFilterDup(fs.conf.List)
	fs.confLock.Unlock()
}

// SetConfig - set new configuration settings
func (fs *filterStg) SetConfig(c Conf) {
	fs.conf.UpdateIntervalHours = c.UpdateIntervalHours
}

// SetObserver - set user handler for notifications
func (fs *filterStg) SetObserver(handler EventHandler) {
	fs.observer = handler
}

// NotifyObserver - notify users about the event
func (fs *filterStg) NotifyObserver(flags uint) {
	if fs.observer == nil {
		return
	}
	fs.observer(flags)
}

// List (thread safe)
func (fs *filterStg) List(flags uint) []Filter {
	fs.confLock.Lock()
	list := make([]Filter, len(fs.conf.List))
	for i, f := range fs.conf.List {
		nf := f
		nf.Path = fs.filePath(f)
		list[i] = nf
	}
	fs.confLock.Unlock()
	return list
}

// Add - add filter (thread safe)
func (fs *filterStg) Add(nf Filter) error {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	for _, f := range fs.conf.List {
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
	fs.conf.List = append(fs.conf.List, nf)
	log.Debug("Filters: added filter %s", nf.URL)
	return nil
}

// Delete - remove filter (thread safe)
func (fs *filterStg) Delete(url string) *Filter {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	nf := []Filter{}
	var found *Filter
	for i := range fs.conf.List {
		f := &fs.conf.List[i]

		if f.URL == url {
			found = f
			continue
		}
		nf = append(nf, *f)
	}
	if found == nil {
		return nil
	}
	fs.conf.List = nf
	log.Debug("Filters: removed filter %s", url)
	found.Path = fs.filePath(*found) // the caller will delete the file
	return found
}

// Modify - set filter properties (thread safe)
// Return Status* bitarray
func (fs *filterStg) Modify(url string, enabled bool, name string, newURL string) (int, Filter, error) {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	st := 0

	for i := range fs.conf.List {
		f := &fs.conf.List[i]
		if f.URL == url {

			backup := *f
			f.Name = name

			if f.Enabled != enabled {
				f.Enabled = enabled
				st |= StatusChangedEnabled
			}

			if f.URL != newURL {
				f.URL = newURL
				st |= StatusChangedURL
			}

			needDownload := false

			if (st & StatusChangedURL) != 0 {
				f.ID = fs.nextFilterID()
				needDownload = true

			} else if (st&StatusChangedEnabled) != 0 && enabled {
				fname := fs.filePath(*f)
				file, err := os.OpenFile(fname, os.O_RDONLY, 0)
				if err != nil {
					log.Debug("Filters: os.OpenFile: %s %s", fname, err)
					needDownload = true
				} else {
					_ = parseFilter(f, file)
					file.Close()
				}
			}

			if needDownload {
				f.LastModified = ""
				f.RuleCount = 0
				err := fs.downloadFilter(f)
				if err != nil {
					*f = backup
					return 0, Filter{}, err
				}
			}

			return st, backup, nil
		}
	}

	return 0, Filter{}, fmt.Errorf("filter %s not found", url)
}

// Get filter file name
func (fs *filterStg) filePath(f Filter) string {
	return filepath.Join(fs.conf.FilterDir, fmt.Sprintf("%d.txt", f.ID))
}

// Get next filter ID
func (fs *filterStg) nextFilterID() uint64 {
	return fs.nextID.Inc()
}
