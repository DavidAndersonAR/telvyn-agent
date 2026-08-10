package checks

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// O motivo da falha precisa CHEGAR no backend, e só quando muda.
//
// Caso real (produção, 10/08): o SNMP do "FiberHome Central" falhava, o agente
// escrevia o motivo no log DESTA máquina e publicava só um contador. A tela do
// equipamento mostrava "warning" e mais nada — descobrir o porquê exigia SSH.

type reporteRegistrado struct {
	checkID string
	ok      bool
	msg     string
}

func coletorDeReportes() (StatusReporter, func() []reporteRegistrado) {
	var mu sync.Mutex
	var got []reporteRegistrado
	f := func(checkID string, ok bool, message string) {
		mu.Lock()
		got = append(got, reporteRegistrado{checkID, ok, message})
		mu.Unlock()
	}
	return f, func() []reporteRegistrado {
		mu.Lock()
		defer mu.Unlock()
		return append([]reporteRegistrado(nil), got...)
	}
}

// espera até cond() virar true ou estourar o prazo — os checks rodam em
// goroutine, então asserção direta depois do Reload é flaky.
func esperar(t *testing.T, cond func() bool) bool {
	t.Helper()
	prazo := time.Now().Add(3 * time.Second)
	for time.Now().Before(prazo) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func TestStatusReporter_FalhaReportaOMotivo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	falha := errors.New("snmp: request timeout")
	reg.Register("t.falha", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return &countingCheck{id: cfg.CheckId, interval: 50 * time.Millisecond,
			runFunc: func(context.Context) ([]*collectorv1.Metric, error) { return nil, falha }}, nil
	})

	rt, _ := makeRuntime(ctx, reg)
	f, ler := coletorDeReportes()
	rt.SetStatusReporter(f)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("c1", "t.falha", 50*time.Millisecond)})

	if !esperar(t, func() bool { return len(ler()) > 0 }) {
		t.Fatal("nada reportado — o motivo ficou preso no agente de novo")
	}
	r := ler()[0]
	if r.ok || r.msg != "snmp: request timeout" || r.checkID != "c1" {
		t.Fatalf("reporte errado: %+v", r)
	}
}

func TestStatusReporter_NaoRepeteEnquantoNadaMuda(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	reg.Register("t.falha", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return &countingCheck{id: cfg.CheckId, interval: 20 * time.Millisecond,
			runFunc: func(context.Context) ([]*collectorv1.Metric, error) {
				return nil, errors.New("mesma falha de sempre")
			}}, nil
	})

	rt, _ := makeRuntime(ctx, reg)
	f, ler := coletorDeReportes()
	rt.SetStatusReporter(f)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("c1", "t.falha", 20*time.Millisecond)})

	// Deixa rodar vários ticks. Um agente com 50 checks quebrados não pode
	// virar 50 POSTs por minuto sem novidade nenhuma.
	if !esperar(t, func() bool { return len(ler()) > 0 }) {
		t.Fatal("nada reportado")
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(ler()); n != 1 {
		t.Fatalf("reportou %d vezes; devia ser 1 (só a mudança)", n)
	}
}

func TestStatusReporter_RecuperacaoReportaOK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var falhando = true
	var mu sync.Mutex
	reg := NewRegistry()
	reg.Register("t.instavel", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return &countingCheck{id: cfg.CheckId, interval: 20 * time.Millisecond,
			runFunc: func(context.Context) ([]*collectorv1.Metric, error) {
				mu.Lock()
				defer mu.Unlock()
				if falhando {
					return nil, errors.New("community errada")
				}
				return nil, nil
			}}, nil
	})

	rt, _ := makeRuntime(ctx, reg)
	f, ler := coletorDeReportes()
	rt.SetStatusReporter(f)
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("c1", "t.instavel", 20*time.Millisecond)})

	if !esperar(t, func() bool { return len(ler()) > 0 }) {
		t.Fatal("nem a falha foi reportada")
	}
	mu.Lock()
	falhando = false
	mu.Unlock()

	// Voltar a funcionar tem que limpar o erro na tela — senão o equipamento
	// fica marcado como quebrado pra sempre.
	if !esperar(t, func() bool {
		rs := ler()
		return len(rs) >= 2 && rs[len(rs)-1].ok
	}) {
		t.Fatalf("recuperação não reportada: %+v", ler())
	}
}

func TestStatusReporter_SemReporterNaoQuebra(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg := NewRegistry()
	reg.Register("t.falha", func(cfg *collectorv1.CheckConfig) (Check, error) {
		return &countingCheck{id: cfg.CheckId, interval: 20 * time.Millisecond,
			runFunc: func(context.Context) ([]*collectorv1.Metric, error) { return nil, errors.New("x") }}, nil
	})

	rt, _ := makeRuntime(ctx, reg) // sem SetStatusReporter — modo legado
	rt.Reload([]*collectorv1.CheckConfig{cfgFor("c1", "t.falha", 20*time.Millisecond)})
	time.Sleep(100 * time.Millisecond) // se entrasse em pânico, o teste caía aqui
}
