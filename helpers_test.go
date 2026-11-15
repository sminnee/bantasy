package bantasy

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeClock is a settable clock for rule sets and trap bans.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// captureLog sends the plugin log to a buffer for the rest of the test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()

	buf := &bytes.Buffer{}
	logger.SetOutput(buf)
	t.Cleanup(func() { logger.SetOutput(os.Stdout) })

	return buf
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.WriteString(data); err != nil {
		t.Fatal(err)
	}

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func tempPath(t *testing.T, name string) string {
	t.Helper()

	return filepath.Join(t.TempDir(), name)
}
