package proxy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

type shortAuditWriter struct{}

func (shortAuditWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }
func TestMultiAuditReportsShortWrite(t *testing.T) {
	audit := NewMultiAudit(shortAuditWriter{}, "", "", nil)
	n, err := audit.Write([]byte("record"))
	if n != 5 || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Write = %d, %v", n, err)
	}
}
func TestMultiAuditReportsFileFailureAndWritesPrimary(t *testing.T) {
	var primary bytes.Buffer
	audit := NewMultiAudit(&primary, "", "", nil)
	// A regular file cannot serve as a directory. Use a file within the temp directory.
	audit.logDir = t.TempDir()
	blocker := audit.logDir + "/blocker"
	if err := os.WriteFile(blocker, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	audit.logDir = blocker
	_, err := audit.Write([]byte("record"))
	if err == nil || primary.String() != "record" {
		t.Fatalf("error=%v primary=%q", err, primary.String())
	}
}
