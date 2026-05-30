// Package ebpf — ContainerResolver: PID → service.name baseado na imagem do
// container Docker que o PID pertence. Usado em ambientes bare-metal (sem
// k8s) onde o PodResolver não tem dados.
//
// Resultado típico: postgres:16-alpine → "postgres", redis:7-alpine →
// "redis", python:3.12-slim → "python". Imagens custom (sem tag oficial) caem
// pro nome do container ou container_id.
//
// Cache: pid→containerID (30s TTL) + containerID→image (5min TTL). Inspect
// docker é HTTP local, mas evita pressão sob alto RPS de eBPF.
package ebpf

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"

	"github.com/ispwatch/collector/internal/ebpf/cgroup"
)

// ContainerResolver resolve um PID a um service.name derivado da imagem
// do container Docker. Retorna ("", false) se PID não tá em container ou
// se Docker não responde.
//
// ResolveServiceByIP resolve um IP de destino (server-side de uma conexão
// outbound) ao service.name do container que possui esse IP. Usado pra
// preencher net.peer.name nos spans outbound em bare-metal — sem isso o
// edge builder do backend descarta spans HTTP por falta de target.
type ContainerResolver interface {
	ResolveService(pid uint32) (serviceName string, ok bool)
	ResolveServiceByIP(ip string) (serviceName string, ok bool)
}

// DockerContainerResolver implementa ContainerResolver via /var/run/docker.sock.
type DockerContainerResolver struct {
	cli *client.Client

	mu          sync.RWMutex
	pidToID     map[uint32]pidEntry
	idToService map[string]serviceEntry

	ipMu      sync.RWMutex
	ipToSvc   map[string]string // ip → service
	ipExpires time.Time
}

type pidEntry struct {
	containerID string
	expires     time.Time
}
type serviceEntry struct {
	service string
	expires time.Time
}

const (
	pidTTL     = 60 * time.Second
	serviceTTL = 5 * time.Minute
	// ipMapTTL — IPs de container raramente mudam (só em
	// restart/recreate). 30s é compromisso entre frescor e custo de
	// listar+inspecionar todos os containers do daemon.
	ipMapTTL = 30 * time.Second
)

// NewDockerContainerResolver tenta conectar no docker.sock local.
// Retorna nil se o socket não está disponível (host sem Docker).
func NewDockerContainerResolver() (*DockerContainerResolver, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	// Ping rápido pra falhar cedo se o daemon não responde.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := cli.Ping(ctx); err != nil {
		_ = cli.Close()
		return nil, err
	}
	return &DockerContainerResolver{
		cli:         cli,
		pidToID:     make(map[uint32]pidEntry),
		idToService: make(map[string]serviceEntry),
		ipToSvc:     make(map[string]string),
	}, nil
}

// ResolveService faz pid → containerID (via cgroup) → image (via Docker
// inspect) → service name. Retorna ("", false) se PID não pertence a um
// container Docker.
func (r *DockerContainerResolver) ResolveService(pid uint32) (string, bool) {
	if r == nil {
		return "", false
	}
	cid := r.containerIDFor(pid)
	if cid == "" {
		return "", false
	}
	svc := r.serviceFor(cid)
	if svc == "" {
		return "", false
	}
	return svc, true
}

func (r *DockerContainerResolver) containerIDFor(pid uint32) string {
	now := time.Now()
	r.mu.RLock()
	e, ok := r.pidToID[pid]
	r.mu.RUnlock()
	if ok && now.Before(e.expires) {
		return e.containerID
	}
	cg, err := cgroup.NewFromProcessCgroupFile("/proc/" + uitoa(pid) + "/cgroup")
	var id string
	if err == nil {
		id = cg.ContainerId
	}
	r.mu.Lock()
	r.pidToID[pid] = pidEntry{containerID: id, expires: now.Add(pidTTL)}
	r.mu.Unlock()
	return id
}

// ResolveServiceByIP faz ip → service.name iterando containers do daemon.
// Constrói um snapshot de todos os IPs em uso (default bridge + cada network
// custom) e cacheia por 30s. Miss = ("", false), sem fallback — bridge.go
// decide o que fazer (geralmente: não escrever net.peer.name).
//
// Cobertura: só containers gerenciados pelo Docker local. Conexões pra hosts
// remotos, gateways de rede, ou processos fora de container não resolvem
// — esse é o comportamento esperado (não somos um DNS).
func (r *DockerContainerResolver) ResolveServiceByIP(ip string) (string, bool) {
	if r == nil || ip == "" {
		return "", false
	}
	r.refreshIPMapIfStale()
	r.ipMu.RLock()
	svc, ok := r.ipToSvc[ip]
	r.ipMu.RUnlock()
	if !ok || svc == "" {
		return "", false
	}
	return svc, true
}

// refreshIPMapIfStale reconstrói o ip→service map se o snapshot atual já
// passou do TTL. Lista todos os containers running e pega o nome de serviço
// dos Labels/Names da Summary (sem inspect individual — barato).
func (r *DockerContainerResolver) refreshIPMapIfStale() {
	now := time.Now()
	r.ipMu.RLock()
	fresh := now.Before(r.ipExpires)
	r.ipMu.RUnlock()
	if fresh {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	containers, err := r.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		// Falha silenciosa: cacheia map vazio com TTL curto pra não bater
		// no daemon em loop. Próxima janela tenta de novo.
		r.ipMu.Lock()
		r.ipToSvc = map[string]string{}
		r.ipExpires = now.Add(ipMapTTL)
		r.ipMu.Unlock()
		return
	}

	next := make(map[string]string, len(containers)*2)
	for _, c := range containers {
		svc := deriveServiceNameFromSummary(c)
		if svc == "" || c.NetworkSettings == nil {
			continue
		}
		for _, ep := range c.NetworkSettings.Networks {
			if ep == nil {
				continue
			}
			if ep.IPAddress != "" {
				next[ep.IPAddress] = svc
			}
			if ep.GlobalIPv6Address != "" {
				next[ep.GlobalIPv6Address] = svc
			}
		}
	}
	r.ipMu.Lock()
	r.ipToSvc = next
	r.ipExpires = now.Add(ipMapTTL)
	r.ipMu.Unlock()
}

// deriveServiceNameFromSummary aplica a mesma lógica de deriveServiceName
// mas operando sobre container.Summary (do ContainerList) em vez de
// InspectResponse — evita N inspects pra montar o ip map.
func deriveServiceNameFromSummary(s container.Summary) string {
	if v := s.Labels["com.docker.compose.service"]; v != "" {
		return sanitize(v)
	}
	if len(s.Names) > 0 {
		name := strings.TrimPrefix(s.Names[0], "/")
		if name != "" {
			return sanitize(name)
		}
	}
	img := s.Image
	if i := strings.LastIndex(img, "/"); i >= 0 {
		img = img[i+1:]
	}
	if i := strings.Index(img, ":"); i >= 0 {
		img = img[:i]
	}
	return sanitize(img)
}

func (r *DockerContainerResolver) serviceFor(cid string) string {
	now := time.Now()
	r.mu.RLock()
	e, ok := r.idToService[cid]
	r.mu.RUnlock()
	if ok && now.Before(e.expires) {
		return e.service
	}

	// Docker inspect é HTTP local — sub-segundo. Falha silenciosa cacheia ""
	// pra não bater no daemon sob loop.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	info, err := r.cli.ContainerInspect(ctx, cid)
	svc := ""
	if err == nil {
		svc = deriveServiceName(info)
	}
	r.mu.Lock()
	r.idToService[cid] = serviceEntry{service: svc, expires: now.Add(serviceTTL)}
	r.mu.Unlock()
	return svc
}

// deriveServiceName escolhe o melhor identificador pra usar como service.name:
//  1. Label "com.docker.compose.service" (compose) — ex: "postgres" / "api"
//  2. Container name sem prefixo "/" — útil quando rodando sem compose
//  3. Image name sem tag/registry — fallback final
//
// Resultado é sanitizado pra ASCII minúsculo + hífen.
func deriveServiceName(info container.InspectResponse) string {
	if info.Config != nil {
		if v := info.Config.Labels["com.docker.compose.service"]; v != "" {
			return sanitize(v)
		}
	}
	name := strings.TrimPrefix(info.Name, "/")
	if name != "" {
		return sanitize(name)
	}
	img := info.Config.Image
	if i := strings.LastIndex(img, "/"); i >= 0 {
		img = img[i+1:]
	}
	if i := strings.Index(img, ":"); i >= 0 {
		img = img[:i]
	}
	return sanitize(img)
}

func sanitize(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "_", "-")
	// Drop nada além de [a-z0-9-]
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		out = "unknown"
	}
	return out
}

func uitoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
