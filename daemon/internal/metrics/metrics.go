// Package metrics writes the Prometheus text exposition format (version
// 0.0.4) with the standard library only.
package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Writer accumulates samples. HELP and TYPE are written before a metric's
// first sample; all samples of one metric must be written together.
type Writer struct {
	buf  bytes.Buffer
	seen map[string]bool
}

// Gauge writes a gauge sample. labels are name, value pairs.
func (w *Writer) Gauge(name, help string, v float64, labels ...string) {
	w.sample(name, "gauge", help, v, labels)
}

// Counter writes a counter sample (name should end in _total).
func (w *Writer) Counter(name, help string, v float64, labels ...string) {
	w.sample(name, "counter", help, v, labels)
}

func (w *Writer) sample(name, typ, help string, v float64, labels []string) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if !w.seen[name] {
		w.seen[name] = true
		fmt.Fprintf(&w.buf, "# HELP %s %s\n# TYPE %s %s\n", name, escape(help, false), name, typ)
	}
	w.buf.WriteString(name)
	if len(labels) > 0 {
		w.buf.WriteByte('{')
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				w.buf.WriteByte(',')
			}
			fmt.Fprintf(&w.buf, "%s=\"%s\"", labels[i], escape(labels[i+1], true))
		}
		w.buf.WriteByte('}')
	}
	w.buf.WriteByte(' ')
	w.buf.WriteString(strconv.FormatFloat(v, 'g', -1, 64))
	w.buf.WriteByte('\n')
}

func escape(s string, quote bool) string {
	r := strings.NewReplacer(`\`, `\\`, "\n", `\n`)
	if quote {
		r = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)
	}
	return r.Replace(s)
}

// Bytes returns what was written.
func (w *Writer) Bytes() []byte { return w.buf.Bytes() }

// Handler serves the samples collect writes, at every request.
func Handler(collect func(*Writer)) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var w Writer
		collect(&w)
		rw.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		rw.Write(w.Bytes())
	})
}
