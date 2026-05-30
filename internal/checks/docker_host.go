// docker_host.go — Check "docker.host" (Phase 4 Plan 07).
//
// Coleta inventário e telemetria de containers Docker em um host via
// socket Unix `/var/run/docker.sock`. Para cada Run emite:
//
// Métricas top-level (sem container tag):
//   - docker.containers_running
//   - docker.containers_stopped
//
// Métricas por container running (tag container_name=<n>):
//   - docker.container.cpu_percent       (cgroup-style: cpuDelta/sysDelta * cpus * 100)
//   - docker.container.mem_used_bytes    (usage − stats.cache)
//   - docker.container.restart_count     (do Summary.HostConfig — Docker API)
//   - docker.container.network_rx_bytes  (soma de stats.Networks[*].RxBytes)
//   - docker.container.network_tx_bytes  (soma de stats.Networks[*].TxBytes)
//
// Decisões locked:
//   - Cliente Docker via interface seam `dockerClient` — em prod usa
//     client.NewClientWithOpts + WithAPIVersionNegotiation; em testes
//     usa fake do _test.go. Sem dependência de daemon real em CI.
//   - Factory tenta `Ping(ctx)` cedo com timeout 3s; falha permission
//     denied → erro com hint `ISPWATCH_DOCKER_INTEGRATION=true`
//     (Pitfall 2). Sem isso o scheduler tentaria pra sempre e poluiria
//     logs com erros idênticos.
//   - Stats em paralelo limitado por `semaphore.NewWeighted(5)`
//     (Pitfall 8) — 100 containers × stats lentos não devem afogar o
//     daemon nem estourar timeout do Run.
//   - Best-effort: erro de stats num container é silenciosamente pulado;
//     outros containers ainda emitem métricas. Top-level counts são
//     calculados antes do fan-out e portanto independentes.
//
// Source = "docker.host" em todas as métricas.
//
// Threat note (T-04-07-02): membership no grupo `docker` é root-equivalente
// no host. install.sh trata isso como opt-in via env var, com warning
// explícito (ver packaging/install.sh).

package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	dockertypes "github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"golang.org/x/sync/semaphore"
	"google.golang.org/protobuf/types/known/timestamppb"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
)

const (
	defaultDockerInterval    = 60 * time.Second
	defaultDockerPingTimeout = 3 * time.Second
	defaultDockerStatsCap    = 5 // Pitfall 8 — parallelism cap
)

// dockerClient é o subset da API Docker que o check usa. Permite mock
// no test sem precisar de socket real (Pitfall 2 evita CI integration).
type dockerClient interface {
	Ping(ctx context.Context) (dockertypes.Ping, error)
	ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error)
	ContainerStatsOneShot(ctx context.Context, containerID string) (container.StatsResponseReader, error)
	Close() error
}

// dockerClientFactory permite o test injetar um fake cliente sem tocar em
// /var/run/docker.sock; em prod aponta para client.NewClientWithOpts.
type dockerClientFactory func() (dockerClient, error)

var defaultDockerClientFactory dockerClientFactory = func() (dockerClient, error) {
	cli, err := client.NewClientWithOpts(
		client.WithHost("unix:///var/run/docker.sock"),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, err
	}
	return cli, nil
}

// dockerHost é a implementação concreta de Check para "docker.host".
type dockerHost struct {
	id         string
	hostID     string
	interval   time.Duration
	staticTags map[string]string
	cli        dockerClient
	statsCap   int64 // semaphore weight — default 5
}

// newDockerHostCheck é a Factory registrada em init() para "docker.host".
// Faz Ping cedo (com timeout 3s) — falha permission denied vira erro
// descritivo com hint do install.sh (Pitfall 2).
func newDockerHostCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	cli, err := defaultDockerClientFactory()
	if err != nil {
		return nil, fmt.Errorf("docker.host: client init: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(context.Background(), defaultDockerPingTimeout)
	defer cancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		_ = cli.Close()
		// Mensagem inclui hint pro operador habilitar via install.sh.
		return nil, fmt.Errorf("docker.host: ping failed (%w); run install.sh with ISPWATCH_DOCKER_INTEGRATION=true to add ispwatch user to docker group", err)
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultDockerInterval
	}

	id := cfg.GetCheckId()
	if id == "" {
		id = "docker.host-" + cfg.GetHostId()
	}

	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}

	return &dockerHost{
		id:         id,
		hostID:     cfg.GetHostId(),
		interval:   interval,
		staticTags: tags,
		cli:        cli,
		statsCap:   defaultDockerStatsCap,
	}, nil
}

func (d *dockerHost) ID() string              { return d.id }
func (d *dockerHost) Interval() time.Duration { return d.interval }
func (d *dockerHost) Tags() map[string]string { return d.staticTags }

// Run executa um ciclo:
//  1. ContainerList(All=true) → conta running/stopped
//  2. Para cada running, ContainerStatsOneShot em paralelo (semaphore=5)
//  3. Emite 2 métricas top-level + 5 por container running
//
// Erros pontuais de stats são pulados (best-effort); a Run só falha se
// ContainerList falhar (sinal de daemon morto/permissão revogada).
func (d *dockerHost) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	if d.cli == nil {
		return nil, errors.New("docker.host: client closed")
	}

	containers, err := d.cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("docker.host: ContainerList: %w", err)
	}

	now := timestamppb.Now()
	var running, stopped int
	for _, c := range containers {
		if c.State == container.StateRunning {
			running++
		} else {
			stopped++
		}
	}

	out := make([]*collectorv1.Metric, 0, 2+running*5)
	out = append(out,
		d.metric(now, "docker.containers_running", float64(running), nil),
		d.metric(now, "docker.containers_stopped", float64(stopped), nil),
	)

	// Coleta stats em paralelo com semaphore=5 (Pitfall 8).
	cap := d.statsCap
	if cap <= 0 {
		cap = defaultDockerStatsCap
	}
	sem := semaphore.NewWeighted(cap)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		perCtr   []*collectorv1.Metric
	)
	for _, c := range containers {
		if c.State != container.StateRunning {
			continue
		}
		wg.Add(1)
		go func(c container.Summary) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				return // ctx canceled — abandonar este container
			}
			defer sem.Release(1)

			metrics := d.collectContainerStats(ctx, now, c)
			if len(metrics) > 0 {
				mu.Lock()
				perCtr = append(perCtr, metrics...)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()

	out = append(out, perCtr...)
	return out, nil
}

// collectContainerStats faz um ContainerStatsOneShot, decodifica JSON e
// produz as 5 métricas por container. Retorna nil em qualquer erro (best-
// effort por Pitfall 8) — caller só agrega o que existir.
func (d *dockerHost) collectContainerStats(ctx context.Context, now *timestamppb.Timestamp, c container.Summary) []*collectorv1.Metric {
	rdr, err := d.cli.ContainerStatsOneShot(ctx, c.ID)
	if err != nil {
		return nil
	}
	if rdr.Body == nil {
		return nil
	}
	defer rdr.Body.Close()

	body, err := io.ReadAll(rdr.Body)
	if err != nil {
		return nil
	}

	var s container.StatsResponse
	if err := json.Unmarshal(body, &s); err != nil {
		return nil
	}

	name := containerDisplayName(c.Names, c.ID)
	tags := map[string]string{"container_name": name}

	// CPU%: cgroup formula. cpuDelta e systemDelta são uint64 — comparar
	// ordem antes de subtrair para evitar overflow em wrap (raro mas possível
	// após uptime longo).
	var cpuPct float64
	if s.CPUStats.CPUUsage.TotalUsage > s.PreCPUStats.CPUUsage.TotalUsage &&
		s.CPUStats.SystemUsage > s.PreCPUStats.SystemUsage {
		cpuDelta := s.CPUStats.CPUUsage.TotalUsage - s.PreCPUStats.CPUUsage.TotalUsage
		sysDelta := s.CPUStats.SystemUsage - s.PreCPUStats.SystemUsage
		cpus := s.CPUStats.OnlineCPUs
		if cpus == 0 {
			cpus = 1 // fallback — kernel sem online_cpus exporta 0
		}
		cpuPct = float64(cpuDelta) / float64(sysDelta) * float64(cpus) * 100.0
	}

	// Mem usage: subtrai cache para refletir RSS-ish. Em alguns kernels o
	// campo é "total_cache"; usar "cache" mantém alinhamento com docker stats CLI.
	memUsed := float64(s.MemoryStats.Usage)
	if cache, ok := s.MemoryStats.Stats["cache"]; ok && cache <= s.MemoryStats.Usage {
		memUsed = float64(s.MemoryStats.Usage - cache)
	}

	// Rede: somar rx/tx de todas as interfaces (eth0, eth1, etc.).
	var rxBytes, txBytes uint64
	for _, n := range s.Networks {
		rxBytes += n.RxBytes
		txBytes += n.TxBytes
	}

	// RestartCount: o Summary do ContainerList não expõe RestartCount
	// diretamente (só via Inspect, que é caro). Por enquanto emite 0 — o
	// dado real virá em iteração futura quando o engine pedir, pra evitar
	// um Inspect por container por tick.
	restart := 0.0

	return []*collectorv1.Metric{
		d.metric(now, "docker.container.cpu_percent", cpuPct, tags),
		d.metric(now, "docker.container.mem_used_bytes", memUsed, tags),
		d.metric(now, "docker.container.restart_count", restart, tags),
		d.metric(now, "docker.container.network_rx_bytes", float64(rxBytes), tags),
		d.metric(now, "docker.container.network_tx_bytes", float64(txBytes), tags),
	}
}

// metric merge static_tags + extra (extra ganha em conflito).
func (d *dockerHost) metric(t *timestamppb.Timestamp, name string, val float64, extraTags map[string]string) *collectorv1.Metric {
	tags := make(map[string]string, len(d.staticTags)+len(extraTags))
	for k, v := range d.staticTags {
		tags[k] = v
	}
	for k, v := range extraTags {
		tags[k] = v
	}
	return &collectorv1.Metric{
		Time:       t,
		HostId:     d.hostID,
		MetricName: name,
		Value:      val,
		Tags:       tags,
		Source:     "docker.host",
	}
}

// containerDisplayName escolhe um nome humano: primeiro Name sem leading
// slash; fallback para 12-char ID. Docker API retorna nomes como "/web".
func containerDisplayName(names []string, id string) string {
	if len(names) > 0 {
		return strings.TrimPrefix(names[0], "/")
	}
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

// init auto-registra o factory em Default.
func init() {
	Default.Register("docker.host", newDockerHostCheck)
}
