// Package svcagg agrega contadores cumulativos por PID que vão ser
// posteriormente atribuídos a "serviços" (systemd unit / container)
// pelo check linux.processes. O bridge eBPF chama Track* em cada
// L7Request observado; o check faz snapshot + PID→cgroup→service na
// hora de emitir as métricas.
//
// Por que aqui (em vez de no próprio bridge): manter o bridge focado em
// "evento → span". Stateful counters num pacote separado deixam o
// contrato claro e permitem outros consumidores no futuro (e.g.,
// dashboards realtime no agent).
//
// L7-payload-only: este pacote conta APENAS bytes do payload L7 (db
// statement, http body, redis command). Não inclui TCP headers, ACKs,
// retransmissões, nem connections idle. Pra monitoramento de "qual
// serviço está produzindo carga de I/O lógica" é suficiente; pra
// medida exata de throughput de rede, use a TrafficStats do
// ConnectionClose (não trazemos aqui pra evitar lag — close pode
// demorar minutos em pool de conn persistente).
package svcagg

import "sync"

// Counters é o snapshot de bytes L7 acumulados pra um PID.
// Campos são cumulativos desde o boot do agent.
type Counters struct {
	NetRx uint64 // bytes de payload L7 que ESTE PID recebeu (request inbound)
	NetTx uint64 // bytes de payload L7 que ESTE PID enviou (request outbound)
}

var (
	mu    sync.RWMutex
	state = make(map[uint32]*Counters, 64)
)

// TrackRx incrementa o contador de bytes L7 recebidos por um PID.
// Chamado pelo bridge eBPF quando um L7Request inbound (IsInbound=true)
// é parseado pra um PID — significa que esse PID é o servidor recebendo
// a request.
func TrackRx(pid uint32, bytes int) {
	if pid == 0 || bytes <= 0 {
		return
	}
	mu.Lock()
	c, ok := state[pid]
	if !ok {
		c = &Counters{}
		state[pid] = c
	}
	c.NetRx += uint64(bytes)
	mu.Unlock()
}

// TrackTx incrementa o contador de bytes L7 enviados por um PID.
// Chamado quando o PID é o cliente (IsInbound=false) — está fazendo
// a request, então saiu bytes pela rede.
func TrackTx(pid uint32, bytes int) {
	if pid == 0 || bytes <= 0 {
		return
	}
	mu.Lock()
	c, ok := state[pid]
	if !ok {
		c = &Counters{}
		state[pid] = c
	}
	c.NetTx += uint64(bytes)
	mu.Unlock()
}

// Snapshot retorna cópia atual dos counters indexados por PID. Usado pelo
// check linux.processes pra cruzar PID → cgroup → service e somar.
func Snapshot() map[uint32]Counters {
	mu.RLock()
	defer mu.RUnlock()
	out := make(map[uint32]Counters, len(state))
	for k, v := range state {
		out[k] = *v
	}
	return out
}

// PruneDead remove entradas pra PIDs que não estão mais vivos.
// Caller passa o conjunto de PIDs ativos (vindo do walk de /proc).
// Evita o mapa crescer infinitamente conforme processos forkam e morrem.
func PruneDead(alive map[uint32]struct{}) {
	mu.Lock()
	defer mu.Unlock()
	for pid := range state {
		if _, ok := alive[pid]; !ok {
			delete(state, pid)
		}
	}
}
