// Package sendbuf — retenção em memória (limitada por bytes) de payloads que
// falharam no envio pro gateway certless, pra reenviar no próximo tick.
//
// Por que existe: o modo mTLS tem WAL em disco, mas o modo ingest não tinha
// NADA — backend fora do ar (rollout, rede) descartava o bucket de apm_stats e
// as métricas do intervalo. Esta fila cobre a queda típica (minutos de rollout);
// queda longa degrada com drop-oldest dentro do teto de bytes — nunca cresce
// sem limite.
//
// Também dá tratamento honesto a duas falhas que retry NÃO conserta:
//   - 401/403: token de ingest inválido/revogado → descarta, entra em
//     cool-down e loga ERRO claro (rate-limited) apontando o env var;
//   - 429: franquia de telemetria do plano estourada → descarta, cool-down
//     maior e aviso claro (o backend corta por 7 dias rolantes — martelar
//     não ajuda).
package sendbuf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// StatusError marca falha HTTP com o código — deixa a fila distinguir
// problema de rede (retém) de auth/franquia (descarta com aviso).
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.Code) }

const (
	authCooldown   = 1 * time.Minute
	budgetCooldown = 5 * time.Minute
	logInterval    = 1 * time.Minute
)

// Queue é a fila de reenvio de UM tipo de payload (ex.: apm-stats). Uso:
// no tick de envio, chame Flush antes do payload novo; se o envio novo
// falhar, entregue o corpo a Offer.
type Queue struct {
	mu          sync.Mutex
	name        string
	maxBytes    int
	items       [][]byte
	bytes       int
	blockedTil  time.Time
	lastAuthLog time.Time
	log         *slog.Logger
}

// New cria a fila. maxBytes limita a soma dos payloads retidos (drop-oldest).
func New(name string, maxBytes int, log *slog.Logger) *Queue {
	if log == nil {
		log = slog.Default()
	}
	return &Queue{name: name, maxBytes: maxBytes, log: log.With("sendbuf", name)}
}

// Blocked = cool-down ativo (token inválido ou franquia estourada); enviar
// agora só repetiria o erro.
func (q *Queue) Blocked() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return time.Now().Before(q.blockedTil)
}

// Flush reenvia o retido (mais antigo primeiro) até esvaziar ou falhar de
// novo. Falha de auth/franquia no meio do flush descarta o item e ativa o
// cool-down (os demais ficam pra próxima janela válida).
func (q *Queue) Flush(ctx context.Context, post func(context.Context, []byte) error) {
	if q.Blocked() {
		return
	}
	for {
		q.mu.Lock()
		if len(q.items) == 0 {
			q.mu.Unlock()
			return
		}
		body := q.items[0]
		q.mu.Unlock()

		if err := post(ctx, body); err != nil {
			if q.noteTerminal(err) {
				q.popFront() // auth/franquia: reenviar não conserta
			}
			return
		}
		q.popFront()
		q.mu.Lock()
		left := len(q.items)
		q.mu.Unlock()
		q.log.Info("payload retido reenviado com sucesso", "restantes", left)
	}
}

// Offer decide o destino de um payload que acabou de falhar com err:
// auth/franquia → descarta (com aviso claro); resto (rede/5xx) → retém.
func (q *Queue) Offer(body []byte, err error) {
	if q.noteTerminal(err) {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = append(q.items, body)
	q.bytes += len(body)
	dropped := 0
	for q.bytes > q.maxBytes && len(q.items) > 1 {
		q.bytes -= len(q.items[0])
		q.items = q.items[1:]
		dropped++
	}
	if dropped > 0 {
		q.log.Warn("fila de reenvio cheia — payloads mais antigos descartados",
			"descartados", dropped, "retidos", len(q.items), "bytes", q.bytes)
	} else {
		q.log.Info("payload retido pra reenvio (backend indisponível)",
			"retidos", len(q.items), "bytes", q.bytes, "err", err)
	}
}

// NoteAuthFailure permite a caminhos sem retenção (ex.: PostRaw de spans)
// registrarem o erro claro de token e ativarem o cool-down compartilhado.
func (q *Queue) NoteAuthFailure(code int) {
	q.noteTerminal(&StatusError{Code: code})
}

// noteTerminal devolve true quando o erro é terminal (auth/franquia): ativa o
// cool-down e loga a mensagem clara (rate-limited).
func (q *Queue) noteTerminal(err error) bool {
	var se *StatusError
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code {
	case 401, 403:
		q.mu.Lock()
		q.blockedTil = time.Now().Add(authCooldown)
		shouldLog := time.Since(q.lastAuthLog) >= logInterval
		if shouldLog {
			q.lastAuthLog = time.Now()
		}
		q.mu.Unlock()
		if shouldLog {
			q.log.Error("token de ingest INVÁLIDO ou REVOGADO — telemetria sendo descartada; "+
				"verifique ISPWATCH_INGEST_TOKEN (gere outro em Monitores → instalar agent)",
				"status", se.Code)
		}
		return true
	case 429:
		q.mu.Lock()
		q.blockedTil = time.Now().Add(budgetCooldown)
		shouldLog := time.Since(q.lastAuthLog) >= logInterval
		if shouldLog {
			q.lastAuthLog = time.Now()
		}
		q.mu.Unlock()
		if shouldLog {
			q.log.Warn("franquia de telemetria do plano EXCEDIDA (HTTP 429) — dados descartados "+
				"até a janela de 7 dias rolar ou o plano subir de tier")
		}
		return true
	}
	return false
}

func (q *Queue) popFront() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return
	}
	q.bytes -= len(q.items[0])
	q.items = q.items[1:]
}
