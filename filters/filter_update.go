package filters

import (
	"os"
	"time"

	"github.com/AdguardTeam/golibs/log"
)

// Refresh - begin filters update procedure
func (fs *filterStg) Refresh(flags uint) {
	fs.confLock.Lock()
	defer fs.confLock.Unlock()

	for i := range fs.conf.List {
		f := &fs.conf.List[i]
		f.nextUpdate = time.Time{}
	}

	fs.updateChan <- true
}

// Start update procedure periodically
func (fs *filterStg) updateByTimer() {
	const maxPeriod = 1 * 60 * 60
	period := 5 // use a dynamically increasing time interval, while network or DNS is down
	for {
		if fs.conf.UpdateIntervalHours == 0 {
			period = maxPeriod
			// update is disabled
			time.Sleep(time.Duration(period) * time.Second)
			continue
		}

		fs.updateChan <- true

		time.Sleep(time.Duration(period) * time.Second)
		period += period
		if period > maxPeriod {
			period = maxPeriod
		}
	}
}

// Begin update procedure by signal
func (fs *filterStg) updateBySignal() {
	for {
		select {
		case ok := <-fs.updateChan:
			if !ok {
				return
			}
			fs.updateAll()
		}
	}
}

// Update filters
// Algorithm:
// . Get next filter to update:
//  . Download data from Internet and store on disk (in a new file)
//  . Add new filter to the special list
//  . Repeat for next filter
// (All filters are downloaded)
// . Stop modules that use filters
// . For each updated filter:
//  . Rename "new file name" -> "old file name"
//  . Update meta data
// . Restart modules that use filters
func (fs *filterStg) updateAll() {
	log.Debug("Filters: updating...")

	for {
		var uf Filter
		fs.confLock.Lock()
		f := fs.getNextToUpdate()
		if f != nil {
			uf = *f
		}
		fs.confLock.Unlock()

		if f == nil {
			fs.applyUpdate()
			return
		}

		uf.ID = fs.nextFilterID()
		err := fs.downloadFilter(&uf)
		if err != nil {
			if uf.networkError {
				fs.confLock.Lock()
				f.nextUpdate = time.Now().Add(10 * time.Second)
				fs.confLock.Unlock()
			}
			continue
		}

		// add new filter to the list
		fs.updated = append(fs.updated, uf)
	}
}

// Get next filter to update
func (fs *filterStg) getNextToUpdate() *Filter {
	now := time.Now()

	for i := range fs.conf.List {
		f := &fs.conf.List[i]

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
		log.Debug("Filters: no filters were updated")
		return
	}

	fs.NotifyObserver(EventBeforeUpdate)

	nUpdated := 0

	fs.confLock.Lock()
	for _, uf := range fs.updated {
		found := false

		for i := range fs.conf.List {
			f := &fs.conf.List[i]

			if uf.URL == f.URL {
				found = true
				fpath := fs.filePath(*f)
				f.LastUpdated = uf.LastUpdated

				if len(uf.Path) == 0 {
					// the data hasn't changed - just update file mod time
					err := os.Chtimes(fpath, f.LastUpdated, f.LastUpdated)
					if err != nil {
						log.Error("Filters: os.Chtimes: %s", err)
					}
					continue
				}

				err := os.Rename(uf.Path, fpath)
				if err != nil {
					log.Error("Filters: os.Rename:%s", err)
				}

				f.RuleCount = uf.RuleCount
				nUpdated++
				break
			}
		}

		if !found {
			// the updated filter was downloaded,
			//  but it's already removed from the main list
			_ = os.Remove(fs.filePath(uf))
		}
	}
	fs.confLock.Unlock()

	log.Debug("Filters: %d filters were updated", nUpdated)

	fs.updated = nil
	fs.NotifyObserver(EventAfterUpdate)
}
