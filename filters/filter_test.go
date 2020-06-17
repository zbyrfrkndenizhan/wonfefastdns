package filters

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
)

func testStartFilterListener(counter *atomic.Uint32) net.Listener {
	mux := http.NewServeMux()

	mux.HandleFunc("/filters/1.txt", func(w http.ResponseWriter, r *http.Request) {
		(*counter).Inc()
		content := `||example.org^$third-party
# Inline comment example
||example.com^$third-party
0.0.0.0 example.com
`
		_, _ = w.Write([]byte(content))
	})

	mux.HandleFunc("/filters/2.txt", func(w http.ResponseWriter, r *http.Request) {
		(*counter).Inc()
		content := `||example.org^$third-party
# Inline comment example
||example.com^$third-party
0.0.0.0 example.com
1.1.1.1 example1.com
`
		_, _ = w.Write([]byte(content))
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	go func() {
		_ = http.Serve(listener, mux)
	}()
	return listener
}

func prepareTestDir() string {
	const dir = "./agh-test"
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0755)
	return dir
}

var updateStatus atomic.Uint32

func onFiltersUpdate(flags uint) {
	switch flags {
	case EventBeforeUpdate:
		updateStatus.Store(updateStatus.Load() | 1)

	case EventAfterUpdate:
		updateStatus.Store(updateStatus.Load() | 2)
	}
}

func TestFilters(t *testing.T) {
	counter := atomic.Uint32{}
	lhttp := testStartFilterListener(&counter)
	defer func() { _ = lhttp.Close() }()

	dir := prepareTestDir()
	defer func() { _ = os.RemoveAll(dir) }()

	fconf := Conf{}
	fconf.UpdateIntervalHours = 1
	fconf.FilterDir = dir
	fconf.HTTPClient = &http.Client{
		Timeout: 5 * time.Second,
	}
	fs := New(fconf)
	fs.SetObserver(onFiltersUpdate)
	fs.Start()

	port := lhttp.Addr().(*net.TCPAddr).Port
	URL := fmt.Sprintf("http://127.0.0.1:%d/filters/1.txt", port)

	// add and download
	f := Filter{
		URL: URL,
	}
	err := fs.Add(f)
	assert.Equal(t, nil, err)

	// check
	l := fs.List(0)
	assert.Equal(t, 1, len(l))
	assert.Equal(t, URL, l[0].URL)
	assert.True(t, l[0].Enabled)
	assert.Equal(t, uint64(3), l[0].RuleCount)
	assert.True(t, l[0].ID != 0)

	// disable
	st, _, err := fs.Modify(f.URL, false, "name", f.URL)
	assert.Equal(t, StatusChangedEnabled, st)

	// check: disabled
	l = fs.List(0)
	assert.Equal(t, 1, len(l))
	assert.True(t, !l[0].Enabled)

	// modify URL
	newURL := fmt.Sprintf("http://127.0.0.1:%d/filters/2.txt", port)
	st, modified, err := fs.Modify(URL, false, "name", newURL)
	assert.Equal(t, StatusChangedURL, st)

	_ = os.Remove(modified.Path)

	// check: new ID, new URL
	l = fs.List(0)
	assert.Equal(t, 1, len(l))
	assert.Equal(t, newURL, l[0].URL)
	assert.Equal(t, uint64(4), l[0].RuleCount)
	assert.True(t, modified.ID != l[0].ID)

	// enable
	st, _, err = fs.Modify(newURL, true, "name", newURL)
	assert.Equal(t, StatusChangedEnabled, st)

	// update
	cnt := counter.Load()
	fs.Refresh(0)
	for i := 0; ; i++ {
		if i == 2 {
			assert.True(t, false)
			break
		}
		if cnt != counter.Load() {
			// filter was updated
			break
		}
		time.Sleep(time.Second)
	}
	assert.Equal(t, uint32(1|2), updateStatus.Load())

	// delete
	removed := fs.Delete(newURL)
	assert.NotNil(t, removed)
	_ = os.Remove(removed.Path)

	fs.Close()
}
