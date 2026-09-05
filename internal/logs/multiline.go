// multiline.go — junta mensagem de log escrita em VÁRIAS linhas num registro só.
//
// O problema. As tags P/F do CRI resolvem só o que o *runtime* partiu (linha
// maior que ~16KB). Mensagem que a APLICAÇÃO escreve em várias linhas passa
// como N registros independentes. No Postgres com log de statement, uma consulta
// vira uma dezena de fragmentos; a tela mostra do mais novo pro mais velho,
// então a consulta aparece de trás pra frente, picotada. Stack trace de Java tem
// o mesmo destino.
//
// A REGRA. Só agregamos DEPOIS de reconhecer positivamente o começo de uma
// mensagem:
//
//	linha começa com data       -> fecha a anterior e ABRE uma nova
//	linha é JSON ({...})        -> sai sozinha (log estruturado já é 1 linha)
//	nenhum dos dois, com aberta -> CONTINUA a que está aberta
//	nenhum dos dois, sem aberta -> sai sozinha (idêntico ao que era antes)
//
// A última regra é o que torna isto seguro: um formato que a gente NÃO
// reconhece nunca abre mensagem, então nunca agrega, então não tem como
// regredir. Só o formato reconhecido muda de comportamento.
//
// Por que não amostrar o arquivo como o Datadog faz. O agente deles decide se
// liga a agregação medindo quantas linhas do começo do arquivo casam com um
// padrão (limiar ~48%). Nesse Postgres a maioria das linhas é continuação de
// consulta — a amostragem DESLIGARIA a agregação justamente no arquivo que mais
// precisa dela. A regra acima não depende de proporção.
//
// Tetos. Mensagem fecha por linha nova, por tempo (mensagem parada), por número
// de linhas e por bytes. Sem o teto de tempo, a última mensagem de um container
// que ficou quieto dormiria no buffer pra sempre.
//
// Concorrência: NÃO é seguro pra uso concorrente. Cada dono usa a sua — o
// tailer CRI cria uma por arquivo (uma goroutine por reader) e o docker cria uma
// só, dentro da goroutine do bridge (que é quem drena o channel).
package logs

import (
	"strings"
	"time"

	"github.com/ispwatch/collector/internal/otlp"
)

const (
	// multilineFlushAfter — mensagem aberta e parada por mais que isso fecha
	// sozinha. O reader do CRI processa tudo que leu no mesmo poll (1s), então
	// só cai aqui a mensagem que estava sendo escrita na virada.
	multilineFlushAfter = 2 * time.Second

	// multilineMaxLines / multilineMaxBytes — tetos de uma mensagem lógica.
	// Estourou, para de colar: a linha seguinte volta a sair sozinha.
	multilineMaxLines = 200
	multilineMaxBytes = 256 * 1024
)

// multilineAggregator junta linhas de continuação na mensagem que as abriu.
type multilineAggregator struct {
	emit func(otlp.LogRecord)
	open map[string]*openMessage // chave = arquivo (CRI) ou container (docker)
}

type openMessage struct {
	rec      otlp.LogRecord // registro da PRIMEIRA linha: dela vêm ts, severidade e attrs
	body     strings.Builder
	lines    int
	lastSeen time.Time
}

func newMultilineAggregator(emit func(otlp.LogRecord)) *multilineAggregator {
	return &multilineAggregator{emit: emit, open: make(map[string]*openMessage)}
}

// Add entrega uma linha já parseada. rec.Body é o texto DAQUELA linha.
func (a *multilineAggregator) Add(key string, rec otlp.LogRecord, now time.Time) {
	text := rec.Body

	if isJSONLine(text) {
		// Log estruturado é sempre uma mensagem inteira: nunca abre nem continua.
		a.flush(key)
		a.emit(rec)
		return
	}

	if startsWithTimestamp(text) {
		a.flush(key)
		m := &openMessage{rec: rec, lines: 1, lastSeen: now}
		m.body.WriteString(text)
		a.open[key] = m
		return
	}

	cur := a.open[key]
	if cur == nil {
		// Formato não reconhecido e nada aberto: comportamento de antes.
		a.emit(rec)
		return
	}
	if cur.lines >= multilineMaxLines || cur.body.Len() >= multilineMaxBytes {
		a.flush(key)
		a.emit(rec)
		return
	}
	cur.body.WriteString("\n")
	cur.body.WriteString(text)
	cur.lines++
	cur.lastSeen = now
}

// Tick fecha as mensagens paradas. Precisa ser chamado com regularidade pelo
// dono — no CRI, a cada poll; no docker, por um ticker no bridge.
func (a *multilineAggregator) Tick(now time.Time) {
	for key, m := range a.open {
		if now.Sub(m.lastSeen) >= multilineFlushAfter {
			a.flush(key)
		}
	}
}

// FlushAll fecha tudo que está aberto (shutdown, rotação de arquivo).
func (a *multilineAggregator) FlushAll() {
	for key := range a.open {
		a.flush(key)
	}
}

func (a *multilineAggregator) flush(key string) {
	m := a.open[key]
	if m == nil {
		return
	}
	delete(a.open, key)
	m.rec.Body = m.body.String()
	a.emit(m.rec)
}

// ---- reconhecimento -----------------------------------------------------

// isJSONLine: começa com '{' e termina com '}'. Não vale parsear de verdade —
// isto roda por linha, e quem precisa dos campos (jsonLogFields) já parseia
// depois. Exigir as duas pontas evita tratar um '{' solto de bloco de código
// como se fosse log estruturado.
func isJSONLine(s string) bool {
	s = strings.TrimSpace(s)
	return len(s) >= 2 && s[0] == '{' && s[len(s)-1] == '}'
}

// startsWithTimestamp diz se a linha ABRE uma mensagem nova.
//
// Reconhece as duas famílias que cobrem a esmagadora maioria dos logs de
// servidor:
//
//	2026-07-31 21:44:57.519 UTC [27] LOG:   (Postgres, Java, Go, ISO/RFC3339…)
//	Jul 31 21:44:57 host daemon:            (syslog)
//
// Espaço ou tabulação à esquerda NÃO é tolerado de propósito: indentação é
// justamente o sinal de continuação. Colchete é, porque "[2026-…" é comum.
//
// Formato que não cai aqui (ex.: access log do nginx, que começa com IP) nunca
// abre mensagem — e portanto nunca agrega. É a saída segura.
func startsWithTimestamp(s string) bool {
	if len(s) > 0 && s[0] == '[' {
		s = s[1:]
	}
	if len(s) < 10 {
		return false
	}
	// YYYY-MM-DD ou YYYY/MM/DD
	if allDigits(s[0:4]) && (s[4] == '-' || s[4] == '/') &&
		allDigits(s[5:7]) && s[7] == s[4] && allDigits(s[8:10]) {
		return true
	}
	return startsWithSyslogTime(s)
}

// startsWithSyslogTime casa "Jul 31 21:44:57" e "Jul  1 21:44:57" (dia alinhado
// com espaço extra).
func startsWithSyslogTime(s string) bool {
	if len(s) < 15 || !isMonthAbbrev(s[0:3]) || s[3] != ' ' {
		return false
	}
	rest := strings.TrimLeft(s[4:], " ")
	day := 0
	for day < len(rest) && rest[day] >= '0' && rest[day] <= '9' {
		day++
	}
	if day == 0 || day > 2 || day >= len(rest) || rest[day] != ' ' {
		return false
	}
	hhmmss := rest[day+1:]
	return len(hhmmss) >= 8 &&
		allDigits(hhmmss[0:2]) && hhmmss[2] == ':' &&
		allDigits(hhmmss[3:5]) && hhmmss[5] == ':' &&
		allDigits(hhmmss[6:8])
}

func isMonthAbbrev(s string) bool {
	switch s {
	case "Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec":
		return true
	}
	return false
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ---- severidade de texto puro -------------------------------------------

// plainTextSeverityScanLimit — só o começo da linha é olhado. Nível de log vem
// no prefixo; "ERROR" no meio da frase é conteúdo, não nível.
const plainTextSeverityScanLimit = 80

// plainTextSeverity acha o nível no prefixo de uma linha de texto puro.
//
// Sem isto, a severidade sai do stream: stdout=INFO, stderr=WARN. O Postgres
// escreve TUDO em stderr, então rotina ("LOG: checkpoint") e falha de verdade
// ("FATAL: …") chegavam com a mesma cara de WARN — e filtrar por erro não
// servia pra nada.
//
// Varre da esquerda pra direita e para no PRIMEIRO token conhecido, então
// "…UTC [27] LOG: could not connect" resolve como INFO (o LOG do Postgres), e
// não como erro por causa da frase.
func plainTextSeverity(s string) (int, string, bool) {
	if len(s) > plainTextSeverityScanLimit {
		s = s[:plainTextSeverityScanLimit]
	}
	for i := 0; i < len(s); {
		if s[i] < 'A' || s[i] > 'Z' {
			i++
			continue
		}
		j := i
		for j < len(s) && s[j] >= 'A' && s[j] <= 'Z' {
			j++
		}
		if j-i >= 3 && j-i <= 9 {
			if n, txt, ok := textLevelToSeverity(s[i:j]); ok {
				return n, txt, true
			}
		}
		i = j
	}
	return 0, "", false
}

// textLevelToSeverity cobre os rótulos do Postgres em cima do mapa geral.
// LOG/NOTICE/DETAIL/HINT/STATEMENT são informativos lá — não são alerta.
func textLevelToSeverity(tok string) (int, string, bool) {
	switch tok {
	case "LOG", "NOTICE", "DETAIL", "HINT", "STATEMENT", "CONTEXT":
		return 9, "INFO", true
	case "PANIC":
		return 21, "FATAL", true
	}
	return levelToSeverity(tok)
}
