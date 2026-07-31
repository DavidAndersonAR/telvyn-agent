package logs

import (
	"strings"
	"testing"
	"time"

	"github.com/ispwatch/collector/internal/otlp"
)

// coletor de saída do agregador, na ordem em que sai.
type sink struct{ recs []otlp.LogRecord }

func (s *sink) push(r otlp.LogRecord) { s.recs = append(s.recs, r) }

func (s *sink) bodies() []string {
	out := make([]string, len(s.recs))
	for i, r := range s.recs {
		out[i] = r.Body
	}
	return out
}

// feed empurra as linhas com 10ms entre elas (longe do teto de tempo) e devolve
// o relógio final.
func feed(a *multilineAggregator, key string, lines []string) time.Time {
	now := time.Unix(1700000000, 0)
	for _, l := range lines {
		a.Add(key, otlp.LogRecord{Body: l, SeverityText: "WARN"}, now)
		now = now.Add(10 * time.Millisecond)
	}
	return now
}

// Saída REAL do postgres-0 no homolog (capturada em 2026-07-31): a consulta
// chega picotada, uma linha física por registro. É o bug que o agregador cura.
var pgLines = []string{
	"2026-07-31 21:44:16.094 UTC [27] LOG:  checkpoint starting: time",
	"2026-07-31 21:44:20.001 UTC [88] LOG:  duration: 91.123 ms  statement: SELECT ia.incident_id",
	"\t         FROM public.noc_incident_alert ia",
	"\t         JOIN public.noc_metric_alert ma ON ma.id = ia.metric_alert_id",
	"\t        WHERE ma.status = 'open'",
	"\t          AND ia.incident_id IS NOT NULL",
	"\t   )",
	"2026-07-31 21:44:57.519 UTC [27] LOG:  checkpoint complete: wrote 279 buffers (1.7%)",
}

func TestPostgresQueryVoltaInteira(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	now := feed(a, "pg", pgLines)
	a.Tick(now.Add(multilineFlushAfter))

	got := s.bodies()
	if len(got) != 3 {
		t.Fatalf("esperava 3 mensagens (2 checkpoints + 1 consulta), veio %d: %q", len(got), got)
	}
	q := got[1]
	for _, frag := range []string{"SELECT ia.incident_id", "FROM public.noc_incident_alert ia", "WHERE ma.status = 'open'", "   )"} {
		if !strings.Contains(q, frag) {
			t.Errorf("pedaço perdido na consulta: %q\nmensagem:\n%s", frag, q)
		}
	}
	if n := strings.Count(q, "\n"); n != 5 {
		t.Errorf("esperava 5 quebras de linha na consulta, veio %d", n)
	}
	// O registro herda o timestamp/severidade da PRIMEIRA linha, não da última.
	if !strings.HasPrefix(q, "2026-07-31 21:44:20.001 UTC [88] LOG:") {
		t.Errorf("mensagem não começa pela linha que a abriu: %q", q[:40])
	}
}

// A regressão que mais assusta: log estruturado começa com '{', que não é data.
// Sem o teste de JSON, toda linha JSON viraria continuação da anterior e o log
// de TODOS os outros serviços quebraria pra consertar o do Postgres.
func TestJSONNuncaVieraContinuacao(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	lines := []string{
		`2026-07-31 21:44:16.094 UTC [27] LOG:  algo`,
		`{"level":"info","msg":"primeira"}`,
		`{"level":"error","msg":"segunda"}`,
		`{"level":"info","msg":"terceira"}`,
	}
	now := feed(a, "app", lines)
	a.Tick(now.Add(multilineFlushAfter))

	if got := s.bodies(); len(got) != 4 {
		t.Fatalf("esperava 4 registros separados, veio %d: %q", len(got), got)
	}
}

// Formato que não reconhecemos nunca abre mensagem — logo nunca agrega, logo
// não tem como regredir. É a garantia que sustenta o desenho todo.
func TestFormatoDesconhecidoSaiLinhaALinha(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	lines := []string{
		`192.168.1.10 - - [31/Jul/2026:21:44:57 +0000] "GET /api/hosts HTTP/1.1" 200 512`,
		`192.168.1.11 - - [31/Jul/2026:21:44:58 +0000] "POST /api/login HTTP/1.1" 403 90`,
		`sem formato nenhum, linha solta`,
	}
	now := feed(a, "nginx", lines)
	a.Tick(now.Add(multilineFlushAfter))

	if got := s.bodies(); len(got) != 3 {
		t.Fatalf("esperava 3 registros, veio %d: %q", len(got), got)
	}
}

func TestStackTraceJavaVemJunto(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	lines := []string{
		"2026-07-31 21:44:20,001 ERROR [io.qua.run] (main) Falhou ao subir:",
		"java.lang.IllegalStateException: boom",
		"\tat system.monitoring.Main.run(Main.java:42)",
		"\tat java.base/java.lang.Thread.run(Thread.java:840)",
		"2026-07-31 21:44:21,100 INFO  [io.qua.run] (main) seguindo",
	}
	now := feed(a, "backend", lines)
	a.Tick(now.Add(multilineFlushAfter))

	got := s.bodies()
	if len(got) != 2 {
		t.Fatalf("esperava 2 mensagens, veio %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "Thread.java:840") {
		t.Errorf("stack trace não veio inteiro:\n%s", got[0])
	}
}

// Containers diferentes escrevem intercalado no mesmo channel (caso docker):
// uma mensagem não pode vazar pra dentro da outra.
func TestChavesNaoSeMisturam(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	now := time.Unix(1700000000, 0)
	a.Add("A", otlp.LogRecord{Body: "2026-07-31 10:00:00 LOG:  de A"}, now)
	a.Add("B", otlp.LogRecord{Body: "2026-07-31 10:00:00 LOG:  de B"}, now)
	a.Add("A", otlp.LogRecord{Body: "\tcontinuação de A"}, now)
	a.Add("B", otlp.LogRecord{Body: "\tcontinuação de B"}, now)
	a.Tick(now.Add(multilineFlushAfter))

	got := s.bodies()
	if len(got) != 2 {
		t.Fatalf("esperava 2 mensagens, veio %d: %q", len(got), got)
	}
	for _, b := range got {
		if strings.Contains(b, "de A") && strings.Contains(b, "de B") {
			t.Errorf("mensagens de containers diferentes coladas: %q", b)
		}
	}
}

// Mensagem aberta e sem sucessor tem que fechar pelo tempo, senão o último log
// de um container quieto some.
func TestMensagemParadaFechaPeloTempo(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	now := time.Unix(1700000000, 0)
	a.Add("pg", otlp.LogRecord{Body: "2026-07-31 10:00:00 LOG:  sozinha"}, now)

	a.Tick(now.Add(multilineFlushAfter / 2))
	if len(s.recs) != 0 {
		t.Fatalf("fechou cedo demais: %q", s.bodies())
	}
	a.Tick(now.Add(multilineFlushAfter))
	if len(s.recs) != 1 {
		t.Fatalf("não fechou no tempo: %q", s.bodies())
	}
}

func TestTetoDeLinhasParaDeColar(t *testing.T) {
	s := &sink{}
	a := newMultilineAggregator(s.push)
	lines := []string{"2026-07-31 10:00:00 LOG:  começo"}
	for i := 0; i < multilineMaxLines+10; i++ {
		lines = append(lines, "\tcontinuação")
	}
	now := feed(a, "pg", lines)
	a.Tick(now.Add(multilineFlushAfter))

	got := s.bodies()
	if len(got) < 2 {
		t.Fatalf("teto não segurou: veio 1 mensagem só")
	}
	if n := strings.Count(got[0], "\n") + 1; n > multilineMaxLines {
		t.Errorf("primeira mensagem passou do teto: %d linhas", n)
	}
}

func TestStartsWithTimestamp(t *testing.T) {
	abre := []string{
		"2026-07-31 21:44:57.519 UTC [27] LOG:  x",
		"2026-07-31T21:44:57.519Z INFO x",
		"2026/07/31 21:44:57 x",
		"[2026-07-31 21:44:57] x",
		"Jul 31 21:44:57 host daemon: x",
		"Jul  1 21:44:57 host daemon: x",
	}
	for _, s := range abre {
		if !startsWithTimestamp(s) {
			t.Errorf("devia abrir mensagem: %q", s)
		}
	}
	naoAbre := []string{
		"\t         FROM public.noc_incident_alert ia",
		"        WHERE ma.status = 'open'",
		"java.lang.IllegalStateException: boom",
		" 2026-07-31 21:44:57 espaço na frente é continuação",
		"192.168.1.10 - - [31/Jul/2026:21:44:57 +0000] GET",
		"",
		"Jun",
	}
	for _, s := range naoAbre {
		if startsWithTimestamp(s) {
			t.Errorf("NÃO devia abrir mensagem: %q", s)
		}
	}
}

func TestPlainTextSeverity(t *testing.T) {
	casos := []struct {
		linha string
		texto string
		ok    bool
	}{
		// O "UTC" antes do nível não pode confundir, e o LOG do Postgres é
		// informativo — não é alerta, mesmo saindo em stderr.
		{"2026-07-31 21:44:57.519 UTC [27] LOG:  checkpoint complete", "INFO", true},
		{"2026-07-31 21:44:57.519 UTC [27] FATAL:  sem espaço em disco", "FATAL", true},
		{"2026-07-31 21:44:57.519 UTC [27] ERROR:  relation does not exist", "ERROR", true},
		{"2026-07-31 21:44:57.519 UTC [27] WARNING:  algo estranho", "WARN", true},
		{"2026-07-31 21:44:20,001 ERROR [io.qua.run] (main) Falhou", "ERROR", true},
		// Primeiro token vence: a palavra na frase não sequestra a severidade.
		{"2026-07-31 21:44:57.519 UTC [27] LOG:  could not connect, see ERROR", "INFO", true},
		// Sem nível nenhum: mantém o que veio do stream.
		{`192.168.1.10 - - [31/Jul/2026:21:44:57 +0000] "GET /api HTTP/1.1" 200`, "", false},
		{"\t         FROM public.noc_incident_alert ia", "", false},
	}
	for _, c := range casos {
		_, txt, ok := plainTextSeverity(c.linha)
		if ok != c.ok || txt != c.texto {
			t.Errorf("plainTextSeverity(%q) = (%q,%v), esperava (%q,%v)", c.linha, txt, ok, c.texto, c.ok)
		}
	}
}

func TestIsJSONLine(t *testing.T) {
	if !isJSONLine(`{"level":"info"}`) {
		t.Error("JSON de uma linha devia casar")
	}
	if isJSONLine("{") {
		t.Error("chave solta (bloco de código) não é JSON")
	}
	if isJSONLine("\tif (x) {") {
		t.Error("linha de código não é JSON")
	}
}
