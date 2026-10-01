package metrics

import (
	"io"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	h := Handler(func(w *Writer) {
		w.Gauge("verilog_wal_bytes", "WAL size.", 42)
		w.Counter("verilog_rejections_total", "Rejections\nby reason.", 3, "reason", "disk_low")
		w.Counter("verilog_rejections_total", "", 0, "reason", `a"b\c`)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body, _ := io.ReadAll(rec.Body)
	want := "# HELP verilog_wal_bytes WAL size.\n# TYPE verilog_wal_bytes gauge\nverilog_wal_bytes 42\n" +
		"# HELP verilog_rejections_total Rejections\\nby reason.\n# TYPE verilog_rejections_total counter\n" +
		"verilog_rejections_total{reason=\"disk_low\"} 3\n" +
		"verilog_rejections_total{reason=\"a\\\"b\\\\c\"} 0\n"
	if string(body) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", body, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content type %q", ct)
	}
}
