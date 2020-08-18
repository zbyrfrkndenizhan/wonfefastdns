package filters

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardHome/util"
	"github.com/AdguardTeam/golibs/log"
)

// Allows printable UTF-8 text with CR, LF, TAB characters
func isPrintableText(data []byte) bool {
	for _, c := range data {
		if (c >= ' ' && c != 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		return false
	}
	return true
}

// Download filter data
// Return nil on success.  Set f.Path to a file path, or "" if the file was not modified
func (fs *filterStg) downloadFilter(f *Filter) error {
	log.Debug("Filters: Downloading filter from %s", f.URL)

	// create temp file
	tmpFile, err := ioutil.TempFile(filepath.Join(fs.conf.FilterDir), "")
	if err != nil {
		return err
	}
	defer func() {
		if tmpFile != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpFile.Name())
		}
	}()

	// create data reader object
	var reader io.Reader
	if filepath.IsAbs(f.URL) {
		f, err := os.Open(f.URL)
		if err != nil {
			return fmt.Errorf("open file: %s", err)
		}
		defer f.Close()
		reader = f
	} else {
		req, err := http.NewRequest("GET", f.URL, nil)
		if err != nil {
			return err
		}

		if len(f.LastModified) != 0 {
			req.Header.Add("If-Modified-Since", f.LastModified)
		}

		resp, err := fs.conf.HTTPClient.Do(req)
		if resp != nil && resp.Body != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			f.networkError = true
			return err
		}

		if resp.StatusCode == 304 { // "NOT_MODIFIED"
			log.Debug("Filters: filter %s isn't modified since %s",
				f.URL, f.LastModified)
			f.LastUpdated = time.Now()
			f.Path = ""
			return nil

		} else if resp.StatusCode != 200 {
			err := fmt.Errorf("Filters: Couldn't download filter from %s: status code: %d",
				f.URL, resp.StatusCode)
			return err
		}

		f.LastModified = resp.Header.Get("Last-Modified")

		reader = resp.Body
	}

	// parse and validate data, write to a file
	err = writeFile(f, reader, tmpFile)
	if err != nil {
		return err
	}

	// Closing the file before renaming it is necessary on Windows
	_ = tmpFile.Close()
	fname := fs.filePath(*f)
	err = os.Rename(tmpFile.Name(), fname)
	if err != nil {
		return err
	}
	tmpFile = nil // prevent from deleting this file in "defer" handler

	log.Debug("Filters: saved filter %s at %s", f.URL, fname)
	f.Path = fname
	f.LastUpdated = time.Now()
	return nil
}

func gatherUntil(dst []byte, dstLen int, src []byte, until int) int {
	num := util.MinInt(len(src), until-dstLen)
	return copy(dst[dstLen:], src[:num])
}

func isHTML(buf []byte) bool {
	s := strings.ToLower(string(buf))
	return strings.Contains(s, "<html") ||
		strings.Contains(s, "<!doctype")
}

// Read file data and count the number of rules
func parseFilter(f *Filter, reader io.Reader) error {
	ruleCount := 0
	r := bufio.NewReader(reader)

	log.Debug("Filters: parsing %s", f.URL)

	var err error
	for err == nil {
		var line string
		line, err = r.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}

		line = strings.TrimSpace(line)

		if len(line) == 0 ||
			line[0] == '#' ||
			line[0] == '!' {
			continue
		}

		ruleCount++
	}

	log.Debug("Filters: %s: %d rules", f.URL, ruleCount)

	f.RuleCount = uint64(ruleCount)
	return nil
}

// Read data, parse, write to a file
func writeFile(f *Filter, reader io.Reader, outFile *os.File) error {
	ruleCount := 0
	buf := make([]byte, 64*1024)
	total := 0
	var chunk []byte

	firstChunk := make([]byte, 4*1024)
	firstChunkLen := 0

	for {
		n, err := reader.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		total += n

		if !isPrintableText(buf[:n]) {
			return fmt.Errorf("data contains non-printable characters")
		}

		if firstChunk != nil {
			// gather full buffer firstChunk and perform its data tests
			firstChunkLen += gatherUntil(firstChunk, firstChunkLen, buf[:n], len(firstChunk))

			if firstChunkLen == len(firstChunk) ||
				err == io.EOF {

				if isHTML(firstChunk[:firstChunkLen]) {
					return fmt.Errorf("data is HTML, not plain text")
				}

				firstChunk = nil
			}
		}

		_, err2 := outFile.Write(buf[:n])
		if err2 != nil {
			return err2
		}

		chunk = append(chunk, buf[:n]...)
		s := string(chunk)
		for len(s) != 0 {
			i, line := splitNext(&s, '\n')
			if i < 0 && err != io.EOF {
				// no more lines in the current chunk
				break
			}
			chunk = []byte(s)

			if len(line) == 0 ||
				line[0] == '#' ||
				line[0] == '!' {
				continue
			}

			ruleCount++
		}

		if err == io.EOF {
			break
		}
	}

	log.Debug("Filters: updated filter %s: %d bytes, %d rules",
		f.URL, total, ruleCount)

	f.RuleCount = uint64(ruleCount)
	return nil
}

// SplitNext - split string by a byte
// Whitespace is trimmed
// Return byte position and the first chunk
func splitNext(data *string, by byte) (int, string) {
	s := *data
	i := strings.IndexByte(s, by)
	var chunk string
	if i < 0 {
		chunk = s
		s = ""

	} else {
		chunk = s[:i]
		s = s[i+1:]
	}

	*data = s
	chunk = strings.TrimSpace(chunk)
	return i, chunk
}
