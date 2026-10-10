package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cautem/slogx"
)

// AuditLine is one OCSF/observation line pushed to a gateway log sink.
type AuditLine struct {
	TS     time.Time
	Source string
	Level  string
	Text   string
}

// LogPusher posts audit lines to a control-plane (optional).
// Implemented by gateway clients outside this module to avoid cycles.
type LogPusher interface {
	PostLogs(ctx context.Context, sandbox string, lines []AuditLine) error
}

const (
	auditBatchSize     = 8
	auditFlushInterval = 2 * time.Second
	auditPushTimeout   = 3 * time.Second
	auditRetentionDays = 3
)

// MultiAudit writes OCSF lines to several sinks (stderr, daily file, gateway).
type MultiAudit struct {
	mu       sync.Mutex
	writers  []io.Writer
	file     *os.File
	fileDay  string
	logDir   string
	pusher   LogPusher
	sandbox  string
	source   string
	buf      []AuditLine
	lastPush time.Time
}

// NewMultiAudit builds sinks. logDir empty skips file; pusher/sandbox empty skips push.
func NewMultiAudit(primary io.Writer, logDir, sandbox string, pusher LogPusher) *MultiAudit {
	if primary == nil {
		primary = os.Stderr
	}
	m := &MultiAudit{
		writers: []io.Writer{primary},
		logDir:  strings.TrimSpace(logDir),
		sandbox: strings.TrimSpace(sandbox),
		source:  "proxy",
		pusher:  pusher,
	}
	if m.sandbox == "" {
		m.pusher = nil
	}
	// File initialization is retried by Write, which reports any failure to its caller.
	_ = m.rotateFileLocked()
	return m
}

func (m *MultiAudit) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeErr := m.rotateFileLocked()
	n := len(p)
	writeSink := func(w io.Writer) {
		written, err := w.Write(p)
		n = min(n, written)
		if written < len(p) && err == nil {
			err = io.ErrShortWrite
		}
		writeErr = errors.Join(writeErr, err)
	}
	for _, w := range m.writers {
		writeSink(w)
	}
	if m.file != nil {
		writeSink(m.file)
	}
	text := strings.TrimRight(string(p), "\r\n")
	if text != "" && m.pusher != nil {
		level := "INFO"
		if strings.Contains(text, "[MED]") {
			level = "MED"
		} else if strings.Contains(text, "[HIGH]") {
			level = "HIGH"
		} else if strings.Contains(text, " OCSF ") {
			level = "OCSF"
		}
		m.buf = append(m.buf, AuditLine{
			TS: time.Now().UTC(), Source: m.source, Level: level, Text: text,
		})
		if len(m.buf) >= auditBatchSize || time.Since(m.lastPush) > auditFlushInterval {
			m.flushGWLocked()
		}
	}
	return n, writeErr
}

func (m *MultiAudit) flushGWLocked() {
	if m.pusher == nil || len(m.buf) == 0 {
		return
	}
	lines := m.buf
	m.buf = nil
	m.lastPush = time.Now()
	pusher := m.pusher
	sandbox := m.sandbox
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), auditPushTimeout)
		defer cancel()
		if err := pusher.PostLogs(ctx, sandbox, lines); err != nil {
			slog.Warn("gateway audit delivery failed", slog.String("sandbox", sandbox), slogx.Err(err))
		}
	}()
}

func (m *MultiAudit) rotateFileLocked() error {
	if m.logDir == "" {
		return nil
	}
	day := time.Now().UTC().Format("2006-01-02")
	if m.file != nil && m.fileDay == day {
		return nil
	}
	if m.file != nil {
		_ = m.file.Close()
		m.file = nil
	}
	if err := os.MkdirAll(m.logDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(m.logDir, "cauteum."+day+".log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	m.file = f
	m.fileDay = day
	// prune old files (keep 3)
	ents, _ := os.ReadDir(m.logDir)
	var logs []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "cauteum.") && strings.HasSuffix(e.Name(), ".log") {
			logs = append(logs, e.Name())
		}
	}
	if len(logs) > auditRetentionDays {
		// best-effort delete oldest by name (YYYY-MM-DD sorts)
		for _, name := range logs[:len(logs)-auditRetentionDays] {
			_ = os.Remove(filepath.Join(m.logDir, name))
		}
	}
	return nil
}

// Close flushes gateway buffer and file.
func (m *MultiAudit) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushGWLocked()
	if m.file != nil {
		return m.file.Close()
	}
	return nil
}

// Ensure MultiAudit is an io.Writer.
var _ io.Writer = (*MultiAudit)(nil)

// LifecycleReady emits a LIFECYCLE line onto w.
func LifecycleReady(w io.Writer, detail string) {
	if w == nil {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	_, _ = fmt.Fprintf(w, "%s OCSF LIFECYCLE:START [INFO] ALLOWED %s\n", ts, detail)
}
