// Package agentstate contém variáveis de estado global do agent que
// precisam ser compartilhadas entre packages sem criar import cycle
// (checks ↔ selfmetrics, principalmente).
//
// Tudo aqui é atomic — mudanças em runtime via config-pull (ex:
// entrega de local_host_id) podem acontecer concorrentemente
// com leituras de selfmetrics.
package agentstate

import "sync/atomic"

var localHostID atomic.Int64

// SetLocalHostID amarra a "identidade ISPWatch" do host físico onde o
// agent roda. Setado via config-pull quando o param local_host_id != 0.
// 0 = não amarrado.
func SetLocalHostID(id int64) {
	localHostID.Store(id)
}

// LocalHostID lê o id atual. Pode mudar entre chamadas (config-pull
// reaplica config), e isso é OK — selfmetrics consulta a cada tick.
func LocalHostID() int64 {
	return localHostID.Load()
}
