// events.go — Phase 3 Plan 05.
//
// Singleton package-level pra emitir Events (distintos de Metrics) do
// agente para o transport. Justificativa: na Wave 3 da Phase 3 apenas
// um Check (snmp.autodiscover) precisa emitir Events; introduzir um
// canal por-Runtime + alterar a interface Check (que retorna so Metrics)
// seria over-engineering pra UM consumer.
//
// Refator esperado quando outro check de eventos aparecer (Phase 4+):
// mover este canal para o Runtime + adicionar um segundo retorno em
// Check.Run([]Metric, []Event, error). Documentado no plan 03-05.
//
// Concorrencia: single-writer (main.go set no startup) + many-readers
// (cada Run de Check chama Get). Lock simples ja resolve.
package checks

import (
	"sync"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

var (
	eventsMu sync.RWMutex
	eventsCh chan<- []*collectorv1.Event
)

// SetEventsChannel instala o canal global para emit de Events. Setar
// nil reverte para "no-op" (o emit silenciosamente descarta). Chamado
// uma vez no startup do main; idempotente.
func SetEventsChannel(ch chan<- []*collectorv1.Event) {
	eventsMu.Lock()
	eventsCh = ch
	eventsMu.Unlock()
}

// EventsChannel retorna o canal atual (pode ser nil). Checks que precisam
// emitir Events fazem uma copia do ptr e enviam non-blocking — se o canal
// estiver cheio (consumidor lento) o lote e dropado com log no caller.
func EventsChannel() chan<- []*collectorv1.Event {
	eventsMu.RLock()
	defer eventsMu.RUnlock()
	return eventsCh
}
