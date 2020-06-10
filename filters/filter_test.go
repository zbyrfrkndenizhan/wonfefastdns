package filters

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func testStartFilterListener() net.Listener {
	http.HandleFunc("/filters/1.txt", func(w http.ResponseWriter, r *http.Request) {
		content := `||example.org^$third-party
# Inline comment example
||example.com^$third-party
0.0.0.0 example.com
`
		_, _ = w.Write([]byte(content))
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}

	go func() { _ = http.Serve(listener, nil) }()
	return listener
}

func prepareTestDir() string {
	const dir = "./agh-test"
	_ = os.RemoveAll(dir)
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func TestFilters(t *testing.T) {
	l := testStartFilterListener()
	defer func() { _ = l.Close() }()

	dir := prepareTestDir()
	defer func() { _ = os.RemoveAll(dir) }()

	fconf := Conf{}
	fconf.FilterDir = dir
	fconf.HTTPClient = &http.Client{
		Timeout: 5 * time.Second,
	}
	ff := New(fconf)
	// ff.Start()

	f := Filter{
		URL: fmt.Sprintf("http://127.0.0.1:%d/filters/1.txt", l.Addr().(*net.TCPAddr).Port),
	}

	// download
	err := ff.Add(f)
	assert.Equal(t, nil, err)

	// refresh
	st, err := ff.Modify(f.URL, false, "name", f.URL)
	assert.Equal(t, StatusChangedEnabled, st)

	rf := ff.Delete(f.URL)
	assert.NotNil(t, rf)
	_ = os.Remove(rf.Path)

	ff.Close()
}
