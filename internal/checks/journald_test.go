package checks

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// fixture inspired by real `journalctl -o json --no-pager` output.
// Mistura: 1 linha INFO normal, 1 linha de WARN, 1 ERROR com stacktrace,
// 1 com PRIORITY ausente (default INFO), 1 da unit poluída init.scope
// (deve ser dropada), 1 com MESSAGE como array de bytes raros.
const journaldFixture = `{"__REALTIME_TIMESTAMP":"1716480001000000","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"GET /healthz 200","PRIORITY":"6","_HOSTNAME":"host-a","_PID":"1234","SYSLOG_IDENTIFIER":"nginx"}
{"__REALTIME_TIMESTAMP":"1716480002500000","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"upstream timed out","PRIORITY":"4","_HOSTNAME":"host-a","_PID":"1234"}
{"__REALTIME_TIMESTAMP":"1716480003000000","_SYSTEMD_UNIT":"app.service","MESSAGE":"java.lang.NullPointerException at com.foo.Bar","PRIORITY":"3","_HOSTNAME":"host-a","_PID":"5678","CODE_FILE":"Bar.java","CODE_LINE":"42"}
{"__REALTIME_TIMESTAMP":"1716480004000000","_SYSTEMD_UNIT":"app.service","MESSAGE":"missing priority field"}
{"__REALTIME_TIMESTAMP":"1716480005000000","_SYSTEMD_UNIT":"init.scope","MESSAGE":"junk we drop","PRIORITY":"6"}
{"__REALTIME_TIMESTAMP":"1716480006000000","_SYSTEMD_UNIT":"weird.service","MESSAGE":[104,105,32,98,121,116,101,115],"PRIORITY":"6"}
`

func TestJournaldParser_BasicMessage(t *testing.T) {
	line := []byte(`{"__REALTIME_TIMESTAMP":"1716480001000000","_SYSTEMD_UNIT":"nginx.service","MESSAGE":"hello","PRIORITY":"6","_HOSTNAME":"h","_PID":"1"}`)
	rec, err := parseJournaldLine(line)
	if err != nil {
		t.Fatalf("parseJournaldLine: %v", err)
	}
	if rec.Unit != "nginx.service" {
		t.Errorf("Unit: got %q want nginx.service", rec.Unit)
	}
	if rec.Body != "hello" {
		t.Errorf("Body: got %q want hello", rec.Body)
	}
	if rec.Priority != 6 {
		t.Errorf("Priority: got %d want 6", rec.Priority)
	}
	// 1716480001000000 µs = 1716480001000000000 ns
	if rec.TimestampUnixNano != 1716480001000000000 {
		t.Errorf("Timestamp: got %d", rec.TimestampUnixNano)
	}
	if rec.Hostname != "h" {
		t.Errorf("Hostname: got %q", rec.Hostname)
	}
}

func TestJournaldParser_BytesMessageDecoded(t *testing.T) {
	// MESSAGE as byte array — rare but valid in journal JSON.
	line := []byte(`{"__REALTIME_TIMESTAMP":"1716480006000000","_SYSTEMD_UNIT":"weird.service","MESSAGE":[104,105,32,98,121,116,101,115],"PRIORITY":"6"}`)
	rec, err := parseJournaldLine(line)
	if err != nil {
		t.Fatalf("parseJournaldLine: %v", err)
	}
	if rec.Body != "hi bytes" {
		t.Errorf("Body decoded: got %q want %q", rec.Body, "hi bytes")
	}
}

func TestJournaldParser_PriorityFallback(t *testing.T) {
	// Missing PRIORITY → default INFO (6).
	line := []byte(`{"__REALTIME_TIMESTAMP":"1716480004000000","_SYSTEMD_UNIT":"x.service","MESSAGE":"no prio"}`)
	rec, _ := parseJournaldLine(line)
	if rec.Priority != 6 {
		t.Errorf("Priority default: got %d want 6", rec.Priority)
	}
}

func TestJournaldParser_UnitFallbackToSyslogIdentifier(t *testing.T) {
	line := []byte(`{"__REALTIME_TIMESTAMP":"1716480001000000","MESSAGE":"hi","PRIORITY":"6","SYSLOG_IDENTIFIER":"sshd"}`)
	rec, _ := parseJournaldLine(line)
	if rec.Unit != "sshd" {
		t.Errorf("Unit fallback: got %q want sshd", rec.Unit)
	}
}

func TestPriorityToSeverityMapping(t *testing.T) {
	cases := map[int][2]any{
		0: {21, "FATAL"},
		1: {21, "FATAL"},
		2: {21, "FATAL"},
		3: {17, "ERROR"},
		4: {13, "WARN"},
		5: {9, "INFO"},
		6: {9, "INFO"},
		7: {5, "DEBUG"},
	}
	for p, want := range cases {
		gotN := PriorityToSeverityNumber(p)
		gotT := PriorityToSeverityText(p)
		if gotN != want[0] {
			t.Errorf("severity_number(%d): got %d want %d", p, gotN, want[0])
		}
		if gotT != want[1] {
			t.Errorf("severity_text(%d): got %q want %q", p, gotT, want[1])
		}
	}
}

func TestJournaldReader_DropsInitScopeAndEmitsRest(t *testing.T) {
	r := NewJournaldReader(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	scanDone := make(chan struct{})
	go func() {
		_ = r.ScanReader(ctx, strings.NewReader(journaldFixture))
		close(scanDone)
	}()

	got := []JournaldRecord{}
	scanFinished := false
	deadline := time.After(2 * time.Second)
loop:
	for {
		select {
		case rec := <-r.out:
			got = append(got, rec)
		case <-scanDone:
			scanFinished = true
			// Drain channel residuals após scan terminar.
			for {
				select {
				case rec := <-r.out:
					got = append(got, rec)
				default:
					break loop
				}
			}
		case <-deadline:
			t.Fatal("timeout draining reader")
		}
	}
	_ = scanFinished
	// 6 linhas → 1 init.scope drop → 5 records esperados.
	if len(got) != 5 {
		t.Fatalf("records: got %d want 5\nrecords=%+v", len(got), got)
	}
	// Spot-checks.
	if got[0].Unit != "nginx.service" || got[0].Body != "GET /healthz 200" {
		t.Errorf("rec[0]: %+v", got[0])
	}
	if got[1].Priority != 4 || got[1].Body != "upstream timed out" {
		t.Errorf("rec[1]: %+v", got[1])
	}
	if got[2].Unit != "app.service" || got[2].Priority != 3 {
		t.Errorf("rec[2]: %+v", got[2])
	}
	// extras coletados: CODE_FILE, CODE_LINE
	if got[2].Extras["code_file"] != "Bar.java" {
		t.Errorf("rec[2] extras code_file missing: %+v", got[2].Extras)
	}
	if got[5-1].Unit != "weird.service" || got[5-1].Body != "hi bytes" {
		t.Errorf("rec[4] bytes-msg decode: %+v", got[5-1])
	}
	// init.scope deve estar ausente.
	for _, rec := range got {
		if rec.Unit == "init.scope" {
			t.Errorf("init.scope should have been dropped, found: %+v", rec)
		}
	}
	stats := r.Stats()
	if stats.LinesTotal != 5 {
		t.Errorf("Stats.LinesTotal: got %d want 5", stats.LinesTotal)
	}
}
