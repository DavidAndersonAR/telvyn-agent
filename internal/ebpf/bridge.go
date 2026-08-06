// bridge.go — adapta eventos L7 do Tracer para spans collectorv1 enviados
// via StreamSpans. Cada Event do tipo EventTypeL7Request vira 1 span com
// atributos semânticos OTel (db.system / db.statement, http.method, etc.).
//
// Esta é a ponte entre a stack eBPF (derivada de coroot-node-agent — ver
// NOTICE) e o pipeline de spans do nosso agent. Sem o SDK OTel completo:
// montamos a struct collectorv1.Span direto, geramos trace_id/span_id via
// crypto/rand, e empurramos pro Forwarder existente.
//
// Cobertura no MVP: HTTP/1.1, Postgres, Redis, MySQL, MongoDB, Memcached,
// ClickHouse. Outros protocolos do upstream (HTTP/2/gRPC, Kafka, Cassandra,
// RabbitMQ, NATS, ZooKeeper) ficam dependentes de parsers stateful — esses
// requerem associar parser por conexão (pid+fd), trabalho futuro.

package ebpf

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"inet.af/netaddr"

	"github.com/ispwatch/collector/internal/ebpf/l7"
	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

// SpanSink é o handler que recebe spans gerados pelo bridge. Implementado
// pelo internal/otlp.Forwarder existente.
type SpanSink interface {
	Push([]*collectorv1.Span)
}

// connKey identifica uma conexão TCP cliente pra associar parsers stateful
// (Postgres usa Parse statement com StatementId; ele precisa de estado).
type connKey struct {
	Pid uint32
	Fd  uint64
}

// parsersByConn mantém parsers stateful (Postgres, MySQL) por conexão.
// Limpos no Close.
type parsersByConn struct {
	mu       sync.Mutex
	postgres map[connKey]*l7.PostgresParser
	mysql    map[connKey]*l7.MysqlParser
}

func newParsersByConn() *parsersByConn {
	return &parsersByConn{
		postgres: map[connKey]*l7.PostgresParser{},
		mysql:    map[connKey]*l7.MysqlParser{},
	}
}

func (p *parsersByConn) postgresFor(k connKey) *l7.PostgresParser {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pp, ok := p.postgres[k]; ok {
		return pp
	}
	pp := l7.NewPostgresParser()
	p.postgres[k] = pp
	return pp
}

func (p *parsersByConn) mysqlFor(k connKey) *l7.MysqlParser {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pp, ok := p.mysql[k]; ok {
		return pp
	}
	pp := l7.NewMysqlParser()
	p.mysql[k] = pp
	return pp
}

// connInfo guarda o destino TCP visto no EventTypeConnectionOpen — usado
// pra preencher net.peer.ip/name nos L7Request events do mesmo (pid, fd),
// que vêm sem DstAddr do kernel.
type connInfo struct {
	dst       netaddr.IPPort
	actualDst netaddr.IPPort
}

type connTracker struct {
	mu sync.RWMutex
	m  map[connKey]connInfo
}

func newConnTracker() *connTracker {
	return &connTracker{m: map[connKey]connInfo{}}
}

func (c *connTracker) put(k connKey, info connInfo) {
	c.mu.Lock()
	c.m[k] = info
	c.mu.Unlock()
}

func (c *connTracker) get(k connKey) (connInfo, bool) {
	c.mu.RLock()
	info, ok := c.m[k]
	c.mu.RUnlock()
	return info, ok
}

func (c *connTracker) delete(k connKey) {
	c.mu.Lock()
	delete(c.m, k)
	c.mu.Unlock()
}

// PodResolver resolve identidade de pods das duas pontas da conexão:
//   - Resolve(pid)    → pod do CLIENTE (caller, lado outbound)
//   - ResolveIP(ip)   → pod do SERVIDOR (callee, lado inbound)
//
// Spans de queries DB (Postgres/Redis/MySQL/...) usam o pod SERVIDOR como
// owner — o tráfego "pertence" ao banco que recebeu, não ao app que pediu.
// É assim que o pod do postgres ganha sua aba "Queries" populada.
type PodResolver interface {
	Resolve(pid uint32) (namespace, pod string, ok bool)
	ResolveIP(ip string) (namespace, pod string, ok bool)
}

// BridgeConfig agrupa parâmetros do bridge.
type BridgeConfig struct {
	ServiceName string // fallback service.name quando PodResolver não responde
	// FallbackHostname identifica este nó em bare-metal. Quando o
	// PodResolver não resolve client nem server (kubelet ausente ou nem
	// uma das pontas é pod K8s), o span ganha ServiceName + Pod =
	// FallbackHostname. Backend cruza com noc_host.hostname pra montar
	// noc_application automaticamente.
	FallbackHostname string
	PodResolver      PodResolver
	// ContainerResolver resolve pid → service.name via Docker quando o
	// PodResolver não tem dados (host bare-metal com Docker). Permite que
	// cada container em compose vire um service distinto (postgres / redis /
	// api) em vez de tudo ser agregado sob o hostname. Nil = skip.
	ContainerResolver ContainerResolver
	Log               *slog.Logger
}

// RunBridge consome events e empurra spans para sink. Bloqueia até ctx
// cancelar ou events fechar.
func RunBridge(ctx context.Context, events <-chan Event, sink SpanSink, cfg BridgeConfig) {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	parsers := newParsersByConn()
	conns := newConnTracker()
	log := cfg.Log.With("component", "ebpf-bridge")

	var totalIn, totalOut, dropped int64
	defer func() {
		log.Info("bridge stopped", "events_in", totalIn, "spans_out", totalOut, "dropped", dropped)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			totalIn++
			// Connection-open/close eventos populam o tracker pra que
			// L7Request events seguintes do mesmo (pid, fd) tenham acesso
			// ao DstAddr — o l7 perf record do kernel não carrega IP.
			switch ev.Type {
			case EventTypeConnectionOpen:
				if ev.Pid != 0 && ev.Fd != 0 {
					conns.put(connKey{Pid: ev.Pid, Fd: ev.Fd}, connInfo{
						dst:       ev.DstAddr,
						actualDst: ev.ActualDstAddr,
					})
				}
				continue
			case EventTypeConnectionClose, EventTypeConnectionError:
				if ev.Pid != 0 && ev.Fd != 0 {
					conns.delete(connKey{Pid: ev.Pid, Fd: ev.Fd})
				}
				continue
			case EventTypeL7Request:
				// segue pro buildSpan
			default:
				continue
			}
			if ev.L7Request == nil {
				continue
			}
			span := buildSpan(ev, parsers, conns, cfg)
			if span == nil {
				dropped++
				continue
			}
			sink.Push([]*collectorv1.Span{span})
			totalOut++
		}
	}
}

// maxL7Latency é o teto de sanidade pra latência de UMA request L7 (HTTP/gRPC/
// DB-query). Acima disso é quase sempre medição corrompida do kernel (underflow
// de end-start numa conexão long-lived) e não um request lento real — ferramentas
// aplica bound parecido nos sinais RED. Streaming/long-poll não são sinal RED e
// caem aqui de propósito. Ajustável se algum protocolo legítimo estourar.
const maxL7Latency = 2 * time.Minute

// physicalL7Latency diz se a duração de 1 request L7 é fisicamente plausível.
// O kernel computa duration = end_ns - start_ns como u64; numa conexão
// long-lived (pool postgres/redis) a resposta pode ser pareada com o request
// errado → end < start → UNDERFLOW, e ao virar time.Duration (int64) fica
// NEGATIVO (o -1.58M ms do cliente) ou inflado pra dezenas de dias (o p95
// "25.1 d"). Filtramos os dois: <=0 e acima do teto. Isola o guard pra teste.
func physicalL7Latency(d time.Duration) bool {
	return d > 0 && d <= maxL7Latency
}

// buildSpan converte 1 Event do tracer em 1 collectorv1.Span. Retorna nil
// quando o protocolo não tem decoder ainda ou quando o payload está vazio.
func buildSpan(ev Event, parsers *parsersByConn, conns *connTracker, cfg BridgeConfig) *collectorv1.Span {
	r := ev.L7Request
	if r == nil {
		return nil
	}

	// Guard de latência L7 não-física: descarta o dado corrompido do kernel na
	// ORIGEM (não conta hit nem latência) antes de envenenar o DDSketch. buildSpan
	// é o único conversor evento→span, então isto limpa noc_span E o stats eBPF
	// (main.go: conc.Add(sp)) de uma vez só.
	if !physicalL7Latency(r.Duration) {
		return nil
	}

	traceID := randomHex(16) // 32 chars
	spanID := randomHex(8)   // 16 chars

	// ev.Timestamp do l7 event é o connection-open time, não o request-end
	// time (perf ring só carrega conexão+duração). Pra conexões long-lived
	// (postgres pool, redis cliente persistente) isso causa spans com
	// timestamps de horas atrás. Tomamos time.Now() na chegada do evento;
	// drift até o request real é < ring delay (<100ms).
	end := time.Now()
	start := end.Add(-r.Duration)

	span := &collectorv1.Span{
		TraceId: traceID,
		SpanId:  spanID,
		// ServiceName fica "" de propósito: a resolução por pod/container abaixo
		// promove o nome real do serviço (serverPod/clientPod). cfg.ServiceName é
		// só o ÚLTIMO fallback (aplicado no fim, se nada resolveu). Pré-preencher
		// aqui fazia TODO span virar "ebpf-tracer" (o `if ServiceName==""` nunca
		// disparava) — era por isso que a lente não distinguia os serviços.
		Kind:          spanKindFor(r.IsInbound),
		StartUnixNano: start.UnixNano(),
		EndUnixNano:   end.UnixNano(),
		Attributes:    map[string]string{},
	}

	// IP do servidor (depois do DNAT do kube-proxy quando aplicável).
	// ActualDstAddr vem da conntrack resolution upstream; quando vazio
	// caímos no DstAddr original (geralmente já é pod IP no eBPF level).
	//
	// L7 perf records do kernel não carregam IP — só Pid+Fd. Consultamos
	// o connTracker que coletou DstAddr do EventTypeConnectionOpen do mesmo
	// (pid, fd). Connection-open vem antes do primeiro L7Request da conexão,
	// então a entrada já está no tracker quando o span é construído.
	actualDst := ev.ActualDstAddr
	dst := ev.DstAddr
	if conns != nil && actualDst.IsZero() && dst.IsZero() && ev.Pid != 0 && ev.Fd != 0 {
		if info, ok := conns.get(connKey{Pid: ev.Pid, Fd: ev.Fd}); ok {
			actualDst = info.actualDst
			dst = info.dst
		}
	}
	serverIP := ""
	serverPort := uint16(0)
	if !actualDst.IsZero() {
		serverIP = actualDst.IP().String()
		serverPort = actualDst.Port()
	} else if !dst.IsZero() {
		serverIP = dst.IP().String()
		serverPort = dst.Port()
	}
	if serverIP != "" {
		span.Attributes["net.peer.ip"] = serverIP
		span.Attributes["net.peer.port"] = fmt.Sprintf("%d", serverPort)
	}
	span.Attributes["process.pid"] = fmt.Sprintf("%d", ev.Pid)

	// Identidade do pod — atribui dependendo do protocolo (DB vs HTTP)
	// no switch abaixo. Resolve as duas pontas antecipadamente.
	var clientNs, clientPod, serverNs, serverPod string
	if cfg.PodResolver != nil {
		clientNs, clientPod, _ = cfg.PodResolver.Resolve(ev.Pid)
		if serverIP != "" {
			serverNs, serverPod, _ = cfg.PodResolver.ResolveIP(serverIP)
		}
	}
	if clientPod != "" {
		span.Attributes["client.namespace"] = clientNs
		span.Attributes["client.pod"] = clientPod
	}
	if serverPod != "" {
		span.Attributes["server.namespace"] = serverNs
		span.Attributes["server.pod"] = serverPod
	}

	// net.peer.name = nome do destino lógico do span. Necessário pro edge
	// builder do backend (TopologyGraphResource.loadEdges) compor edges em
	// spans HTTP — sem db.system e sem peer.service, esse atributo é o
	// único hint de target e sua ausência faz o span virar dst=NULL e
	// ser descartado.
	//
	// Ordem de prioridade:
	//   1. k8s: pod do server resolvido via PodResolver.ResolveIP
	//   2. bare-metal: container Docker dono do IP via ResolveServiceByIP
	//   3. caso contrário: deixa vazio (destino fora do nosso fleet — esperado
	//      pra Google/CDN/DNS público).
	if serverPod != "" {
		// Spec do backend: na rota k8s o "service.name" do pod IS o pod name
		// (linha "if span.ServiceName == "" { span.ServiceName = serverPod }"
		// acima). Mantemos a mesma convenção pra net.peer.name bater no edge.
		span.Attributes["net.peer.name"] = serverPod
	} else if serverIP != "" && cfg.ContainerResolver != nil {
		if peer, ok := cfg.ContainerResolver.ResolveServiceByIP(serverIP); ok {
			span.Attributes["net.peer.name"] = peer
		}
	}

	// Owner do span = pod onde a aba "Queries" do /aplicações vai mostrar.
	// Regra: o pod que RECEBE a request é o owner. Pra eBPF traces no lado
	// client (IsInbound=false, caso comum no eBPF outbound), owner = server
	// (postgres, redis, etc.). Pra spans inbound (server side capturado),
	// owner = o próprio pod cliente (que é o servidor desta perspectiva).
	if !r.IsInbound && serverPod != "" {
		span.Namespace = serverNs
		span.Pod = serverPod
		if span.ServiceName == "" {
			span.ServiceName = serverPod
		}
	} else if clientPod != "" {
		span.Namespace = clientNs
		span.Pod = clientPod
		if span.ServiceName == "" {
			span.ServiceName = clientPod
		}
	} else if cfg.ContainerResolver != nil {
		// Bare-metal com Docker: tenta resolver pid → image/container nome.
		// Cada container em compose vira service distinto (postgres, redis,
		// api) em vez de tudo ser jogado sob o hostname.
		if svc, ok := cfg.ContainerResolver.ResolveService(ev.Pid); ok {
			span.ServiceName = svc
			span.Pod = svc // pod label = service identifier pra reuso no backend
			// Anexa hostname como atributo pra backend ainda conseguir cruzar
			// o span com noc_host (host onde o container roda).
			if cfg.FallbackHostname != "" {
				span.Attributes["host.name"] = cfg.FallbackHostname
			}
		} else if cfg.FallbackHostname != "" {
			// Container sem Docker (systemd raw process) ou Docker daemon
			// offline: cai no comportamento antigo.
			span.Pod = cfg.FallbackHostname
			span.ServiceName = cfg.FallbackHostname
		}
	} else if cfg.FallbackHostname != "" {
		// Bare-metal: kubelet não resolveu nenhuma das pontas. Carimba
		// com hostname pra backend cruzar com noc_host e materializar a
		// noc_application via SpanIngestor.
		span.Pod = cfg.FallbackHostname
		span.ServiceName = cfg.FallbackHostname
	}
	if span.ServiceName == "" {
		// Último fallback: nada resolveu (sem pod, sem container, sem hostname).
		svc := cfg.ServiceName
		if svc == "" {
			svc = "ebpf-tracer"
		}
		span.ServiceName = svc
	}

	// Status do span — OTel: 0 UNSET, 1 OK, 2 ERROR.
	if r.Status.Error() {
		span.StatusCode = 2
	} else if r.Status != 0 {
		span.StatusCode = 1
	}

	// Decoder por protocolo. Cada ramo seta name + db.* attrs.
	switch r.Protocol {
	case l7.ProtocolHTTP:
		method, path := l7.ParseHttp(r.Payload)
		span.Name = method
		span.Attributes["http.method"] = method
		span.Attributes["http.target"] = path
		span.Attributes["http.status_code"] = fmt.Sprintf("%d", int(r.Status))

	case l7.ProtocolPostgres:
		k := connKey{Pid: ev.Pid, Fd: ev.Fd}
		query := parsers.postgresFor(k).Parse(r.Payload)
		if query == "" {
			return nil
		}
		span.Name = "postgres query"
		span.Attributes["db.system"] = "postgresql"
		span.Attributes["db.statement"] = query

	case l7.ProtocolRedis:
		cmd, args := l7.ParseRedis(r.Payload)
		if cmd == "" {
			return nil
		}
		stmt := cmd
		if args != "" {
			stmt += " " + args
		}
		span.Name = cmd
		span.Attributes["db.system"] = "redis"
		span.Attributes["db.operation"] = cmd
		span.Attributes["db.statement"] = stmt

	case l7.ProtocolMysql:
		k := connKey{Pid: ev.Pid, Fd: ev.Fd}
		query := parsers.mysqlFor(k).Parse(r.Payload, r.StatementId)
		if query == "" {
			return nil
		}
		span.Name = "mysql query"
		span.Attributes["db.system"] = "mysql"
		span.Attributes["db.statement"] = query

	case l7.ProtocolMongo:
		query := l7.ParseMongo(r.Payload)
		if query == "" {
			return nil
		}
		span.Name = "mongo query"
		span.Attributes["db.system"] = "mongodb"
		span.Attributes["db.statement"] = query

	case l7.ProtocolMemcached:
		cmd, items := l7.ParseMemcached(r.Payload)
		if cmd == "" {
			return nil
		}
		span.Name = cmd
		span.Attributes["db.system"] = "memcached"
		span.Attributes["db.operation"] = cmd
		if len(items) > 0 {
			span.Attributes["db.memcached.item"] = items[0]
		}

	case l7.ProtocolClickhouse:
		query := l7.ParseClickhouse(r.Payload)
		if query == "" {
			return nil
		}
		span.Name = "clickhouse query"
		span.Attributes["db.system"] = "clickhouse"
		span.Attributes["db.statement"] = query

	case l7.ProtocolDNS:
		span.Name = "dns query"
		span.Attributes["dns.protocol"] = "dns"

	default:
		// HTTP/2/gRPC, Kafka, Cassandra, RabbitMQ, NATS, ZooKeeper, Dubbo,
		// FoundationDB exigem parsers stateful adicionais. Marcamos como
		// "unknown" pra observabilidade mas não dropamos.
		span.Name = r.Protocol.String()
		span.Attributes["protocol"] = r.Protocol.String()
		span.Attributes["protocol.method"] = r.Method.String()
	}

	return span
}

// spanKindFor traduz IsInbound do OTel/eBPF: inbound (server side) = 2,
// outbound (client) = 3. Valores conforme proto Span.
func spanKindFor(isInbound bool) int32 {
	if isInbound {
		return 2 // SERVER
	}
	return 3 // CLIENT
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
