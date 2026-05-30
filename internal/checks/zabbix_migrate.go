// zabbix_migrate.go — Executor de steps de migração de Zabbix vindos do
// backend. Cada step é uma operação no host onde o agent roda: docker stop,
// docker pull, docker run, pg_dump, etc.
//
// Status atual: implementa o caminho DOCKER end-to-end (SNAPSHOT_DB,
// STOP_CONTAINER, PULL_IMAGE, START_CONTAINER, WAIT_HEALTHY, VALIDATE_COUNTS).
// Caminho NATIVE (systemctl + apt) e PG_UPGRADE_DUMP_RESTORE retornam
// 'not_implemented' até o operador habilitar manualmente — abaixar
// produção sem rollback automático é risco alto demais pra V1.
//
// Convenções:
//   - Todos os comandos timeout via context — passos longos (pg_dump 50GB)
//     usam ctx do scheduler (~30min). Pra steps > 30min, a ContextDeadline
//     do scheduler precisa ser estendida no caller (zabbix_sync.go).
//   - stdout/stderr são acumulados em strings.Builder e retornados ao
//     backend (tail dos últimos 4KB).
//   - Snapshot path padrão: /var/lib/ispwatch-collector/snapshots/<step_id>.dump
package checks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// osStatfs envelopa syscall.Statfs pra teste/portabilidade futura. Hoje
// é Linux-only — agent só roda em Linux/WSL.
func osStatfs(path string) (*syscall.Statfs_t, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// stepDTO é o payload retornado por GET /migration-steps.
type stepDTO struct {
	PlanID           string                 `json:"plan_id"`
	StepID           string                 `json:"step_id"`
	Seq              int                    `json:"seq"`
	StepType         string                 `json:"step_type"`
	Params           map[string]interface{} `json:"params"`
	DeploymentMode   string                 `json:"deployment_mode"`
	TargetIdentifier string                 `json:"target_identifier"`
}

// stepResult é o que o agent reporta de volta via POST.
type stepResult struct {
	Status          string                 `json:"status"` // succeeded | failed
	ExitCode        *int                   `json:"exit_code,omitempty"`
	StdoutTail      string                 `json:"stdout_tail,omitempty"`
	StderrTail      string                 `json:"stderr_tail,omitempty"`
	ResultSummary   map[string]interface{} `json:"result_summary,omitempty"`
	SnapshotPath    string                 `json:"snapshot_path,omitempty"`
	SnapshotBytes   *int64                 `json:"snapshot_bytes,omitempty"`
	DurationSeconds int                    `json:"duration_seconds,omitempty"`
}

// snapshotDir retorna onde guardar dumps de DB. Em Linux fica colado ao
// state dir do agent.
func snapshotDir() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/ispwatch-collector/snapshots"
	}
	return "./snapshots"
}

// fetchAndExecOneStep puxa o próximo step e roda. Retorna (ranSomething, err).
// Quando não há step pendente, retorna (false, nil) — caso comum.
func (c *zabbixSyncCheck) fetchAndExecOneStep(ctx context.Context) (bool, error) {
	respBody, err := PostJSONOrGet(ctx, "GET",
		"/api/collector/v1/zabbix/migration-steps?monitor_id="+c.monitorID, nil)
	if err != nil {
		// 204 No Content é normal; nosso PostJSONOrGet só retorna err em status
		// >= 400, então qualquer err aqui é real.
		return false, err
	}
	if len(respBody) == 0 {
		return false, nil
	}
	var step stepDTO
	if err := json.Unmarshal(respBody, &step); err != nil {
		return false, fmt.Errorf("decode step: %w", err)
	}
	if step.StepID == "" {
		return false, nil
	}

	c.log.Info("migration step picked up",
		"step_id", step.StepID, "seq", step.Seq, "type", step.StepType,
		"mode", step.DeploymentMode)

	start := time.Now()
	result := c.dispatchStep(ctx, &step)
	result.DurationSeconds = int(time.Since(start).Seconds())

	if _, err := PostJSON(ctx,
		"/api/collector/v1/zabbix/migration-steps/"+step.StepID+"/result",
		result); err != nil {
		c.log.Warn("post step result failed",
			"step_id", step.StepID, "status", result.Status, "err", err)
		return true, err
	}
	c.log.Info("migration step done",
		"step_id", step.StepID, "status", result.Status,
		"duration_s", result.DurationSeconds)
	return true, nil
}

// dispatchStep escolhe a função por step_type. Falhas viram result.Status=failed
// (não panic); rede/IO viram exit_code=-1 + stderr_tail.
func (c *zabbixSyncCheck) dispatchStep(ctx context.Context, step *stepDTO) stepResult {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("migration step panicked", "panic", r, "step_id", step.StepID)
		}
	}()

	switch step.StepType {
	case "PRE_FLIGHT":
		return c.stepPreflight(ctx, step)
	case "SNAPSHOT_DB":
		return c.stepSnapshotDB(ctx, step)
	case "STOP_CONTAINER":
		return c.stepStopContainer(ctx, step)
	case "PULL_IMAGE":
		return c.stepPullImage(ctx, step)
	case "START_CONTAINER":
		return c.stepStartContainer(ctx, step)
	case "WAIT_HEALTHY":
		return c.stepWaitHealthy(ctx, step)
	case "VALIDATE_COUNTS":
		return c.stepValidateCounts(ctx, step)
	case "ROLLBACK_RESTORE":
		return c.stepRollbackRestore(ctx, step)
	case "STOP_SERVICE":
		return c.stepStopService(ctx, step)
	case "INSTALL_PACKAGE":
		return c.stepInstallPackage(ctx, step)
	case "START_SERVICE":
		return c.stepStartService(ctx, step)

	case "PG_UPGRADE_DUMP_RESTORE":
		return c.stepPgUpgradeDumpRestore(ctx, step)
	}
	return failed(step, "unknown step_type "+step.StepType, -1, "")
}

// ---- step implementations ----

// SNAPSHOT_DB roda pg_dump --format=custom dentro do container PG que serve
// o Zabbix. Descobre o container PG via docker inspect no Zabbix server
// (env DB_HOST aponta pra ele) ou usa o param pg_container_name se vier.
func (c *zabbixSyncCheck) stepSnapshotDB(ctx context.Context, step *stepDTO) stepResult {
	zabbixContainer := step.TargetIdentifier
	pgContainer := strParam(step.Params, "pg_container_name", "")
	dbName := strParam(step.Params, "db_name", "")
	dbUser := strParam(step.Params, "db_user", "")
	if pgContainer == "" || dbName == "" || dbUser == "" {
		info, err := dockerInspectEnv(ctx, zabbixContainer)
		if err != nil {
			return failed(step, "inspect zabbix container", -1, err.Error())
		}
		if pgContainer == "" {
			pgContainer = info["DB_HOST"]
		}
		if dbName == "" {
			if v, ok := info["POSTGRES_DB"]; ok {
				dbName = v
			} else if v, ok := info["DB_NAME"]; ok {
				dbName = v
			}
		}
		if dbUser == "" {
			if v, ok := info["POSTGRES_USER"]; ok {
				dbUser = v
			} else if v, ok := info["DB_USER"]; ok {
				dbUser = v
			}
		}
	}
	if pgContainer == "" || dbName == "" || dbUser == "" {
		return failed(step, "could not resolve PG connection from container env", -1,
			fmt.Sprintf("pg_container=%q db_name=%q db_user=%q",
				pgContainer, dbName, dbUser))
	}

	if err := os.MkdirAll(snapshotDir(), 0o755); err != nil {
		return failed(step, "mkdir snapshot dir", -1, err.Error())
	}
	outPath := filepath.Join(snapshotDir(), "snap-"+step.StepID+".dump")

	// Note: NÃO passamos -u no docker exec porque dbUser é o ROLE do
	// Postgres (passa via -U), não um Linux user dentro do container.
	// O container postgres oficial roda como 'postgres' user, e o
	// pg_dump precisa apenas se autenticar via -U + senha (passada por
	// env PGPASSWORD se o cliente exigir).
	args := []string{
		"exec", pgContainer,
		"pg_dump", "-Fc", "-Z", "1", "-U", dbUser, "-w", dbName,
	}
	stdout, stderr, exitCode, runErr := runWithRedirect(ctx, "docker", args, outPath)
	if runErr != nil || exitCode != 0 {
		os.Remove(outPath)
		msg := "pg_dump failed"
		if runErr != nil {
			msg += ": " + runErr.Error()
		}
		return failed(step, msg, exitCode, tail(stderr+"\n"+stdout, 2000))
	}

	fi, statErr := os.Stat(outPath)
	if statErr != nil {
		return failed(step, "snapshot file missing", exitCode, statErr.Error())
	}
	bytesN := fi.Size()
	return stepResult{
		Status:        "succeeded",
		ExitCode:      ptrInt(0),
		StdoutTail:    tail(stdout, 2000),
		StderrTail:    tail(stderr, 1000),
		SnapshotPath:  outPath,
		SnapshotBytes: &bytesN,
		ResultSummary: map[string]interface{}{
			"pg_container": pgContainer, "db": dbName,
			"bytes": bytesN,
		},
	}
}

func (c *zabbixSyncCheck) stepStopContainer(ctx context.Context, step *stepDTO) stepResult {
	name := step.TargetIdentifier
	if name == "" {
		name = strParam(step.Params, "container_name", "")
	}
	if name == "" {
		return failed(step, "container_name required", -1, "")
	}
	stdout, stderr, code, err := runCmd(ctx, "docker", []string{"stop", name})
	if err != nil || code != 0 {
		return failed(step, "docker stop", code, tail(stderr+"\n"+stdout, 1500))
	}
	return ok(step, code, stdout, stderr, map[string]interface{}{"container": name})
}

func (c *zabbixSyncCheck) stepPullImage(ctx context.Context, step *stepDTO) stepResult {
	image := strParam(step.Params, "image", "")
	if image == "" {
		return failed(step, "image required in params", -1, "")
	}
	stdout, stderr, code, err := runCmd(ctx, "docker", []string{"pull", image})
	if err != nil || code != 0 {
		return failed(step, "docker pull", code, tail(stderr+"\n"+stdout, 2000))
	}
	return ok(step, code, stdout, stderr, map[string]interface{}{"image": image})
}

// START_CONTAINER cria um container NOVO com a imagem nova, mantendo
// o NOME + as env vars + os volumes do antigo. Estratégia conservadora:
//   1. docker inspect <old> --format json → captura Mounts/Env/HostConfig
//   2. docker rm <old> (já parado por STOP_CONTAINER)
//   3. docker run com mesmos mounts + env + nome
//
// O zabbix_server da imagem nova vai detectar dbversion < expected na
// boot e rodar o DB upgrade automaticamente.
func (c *zabbixSyncCheck) stepStartContainer(ctx context.Context, step *stepDTO) stepResult {
	name := step.TargetIdentifier
	if name == "" {
		name = strParam(step.Params, "container_name", "")
	}
	imageTag := strParam(step.Params, "image_tag", "")
	if name == "" || imageTag == "" {
		return failed(step, "container_name + image_tag required", -1, "")
	}
	newImage := "zabbix/zabbix-server-pgsql:" + imageTag

	specJSON, stderr, code, err := runCmd(ctx, "docker", []string{"inspect", name})
	if err != nil || code != 0 {
		return failed(step, "inspect failed", code, tail(stderr, 1500))
	}
	envs, mounts, networks, parseErr := parseInspect(specJSON)
	if parseErr != nil {
		return failed(step, "parse inspect", -1, parseErr.Error())
	}

	// Remove container antigo (deve estar parado pelo step anterior)
	_, _, _, _ = runCmd(ctx, "docker", []string{"rm", name})

	args := []string{"run", "-d", "--name", name, "--restart", "unless-stopped"}
	for _, e := range envs {
		args = append(args, "-e", e)
	}
	for _, m := range mounts {
		args = append(args, "-v", m)
	}
	for _, n := range networks {
		args = append(args, "--network", n)
	}
	args = append(args, newImage)

	stdout, stderr2, code2, err2 := runCmd(ctx, "docker", args)
	if err2 != nil || code2 != 0 {
		return failed(step, "docker run", code2, tail(stderr2+"\n"+stdout, 2000))
	}
	return ok(step, code2, stdout, stderr2, map[string]interface{}{
		"new_image": newImage, "container": name,
	})
}

// WAIT_HEALTHY polla `docker logs --tail 50 <container>` procurando por
// "database is ready" ou "server #0 started [main process]" — sinais que
// o Zabbix terminou o DB upgrade e está aceitando trabalho.
//
// timeout_minutes vem do step (calculado pelo planner baseado em tamanho
// do DB). Em caso de timeout, status=failed.
func (c *zabbixSyncCheck) stepWaitHealthy(ctx context.Context, step *stepDTO) stepResult {
	name := step.TargetIdentifier
	if name == "" {
		name = strParam(step.Params, "container_name", "")
	}
	if name == "" {
		return failed(step, "container_name required", -1, "")
	}
	timeoutMin := intParam(step.Params, "timeout_minutes", 30)
	deadline := time.Now().Add(time.Duration(timeoutMin) * time.Minute)
	lastTail := ""
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return failed(step, "context cancelled while waiting", -1, lastTail)
		default:
		}
		stdout, _, _, _ := runCmd(ctx, "docker", []string{"logs", "--tail", "100", name})
		lastTail = stdout
		if strings.Contains(stdout, "server #0 started") ||
			strings.Contains(stdout, "database is ready") ||
			strings.Contains(stdout, "Zabbix Server stopped") /* shouldn't happen but log */ {
			if strings.Contains(stdout, "Zabbix Server stopped") {
				return failed(step, "container exited during boot", -1, tail(stdout, 2500))
			}
			return ok(step, 0, "ready", "",
				map[string]interface{}{"signal_found": true})
		}
		time.Sleep(5 * time.Second)
	}
	return failed(step, "timeout waiting healthy", -1, tail(lastTail, 2500))
}

// PRE_FLIGHT roda no início do plano (seq=1) pra:
//   1. confirmar que o container/serviço alvo existe e está rodando
//   2. detectar PG version via SELECT version()
//   3. capturar baseline counts (hosts/items/triggers/dbversion)
//   4. checar espaço livre em disco no diretório de snapshots
//
// Resultado vai pra plan.preflight_report no backend, que injeta baseline
// no params do VALIDATE_COUNTS quando o agent buscar aquele step.
//
// Política: falha → plan.preflight_status='blocked' + plano.status='failed'.
// Operador precisa ajustar o ambiente antes de tentar de novo.
func (c *zabbixSyncCheck) stepPreflight(ctx context.Context, step *stepDTO) stepResult {
	summary := map[string]interface{}{}
	dbSizeGb := floatParam(step.Params, "db_size_gb", 10.0)
	minDiskGb := floatParam(step.Params, "min_disk_free_gb", dbSizeGb*1.3)

	// (1) container/serviço alvo
	target := step.TargetIdentifier
	summary["target_identifier"] = target
	if step.DeploymentMode == "DOCKER" {
		stdout, stderr, code, _ := runCmd(ctx, "docker",
			[]string{"inspect", "--format", "{{.State.Status}}|{{.Config.Image}}", target})
		if code != 0 {
			return failed(step,
				"target container '"+target+"' not found via docker inspect",
				code, tail(stderr, 600))
		}
		parts := strings.Split(strings.TrimSpace(stdout), "|")
		if len(parts) >= 2 {
			summary["container_status"] = parts[0]
			summary["container_image"] = parts[1]
		}
	}
	// NATIVE: skip systemctl check pra não falhar em ambiente dev. V2 valida.

	// (2)+(3) PG version + baseline counts (precisa container PG resolvido)
	info, err := dockerInspectEnv(ctx, target)
	if err != nil {
		return failed(step, "could not inspect env of "+target, -1, err.Error())
	}
	pgContainer := info["DB_SERVER_HOST"]
	if pgContainer == "" { pgContainer = info["DB_HOST"] }
	dbName := info["POSTGRES_DB"]
	if dbName == "" { dbName = info["DB_NAME"] }
	dbUser := info["POSTGRES_USER"]
	if dbUser == "" { dbUser = info["DB_USER"] }
	if dbUser == "" { dbUser = "zabbix" }

	// Resolve container PG real (composer prepend project name)
	if pgContainer != "" {
		resolved := resolvePgContainer(ctx, pgContainer)
		if resolved != "" { pgContainer = resolved }
	}
	if pgContainer == "" {
		return failed(step, "could not resolve PG container from env", -1,
			fmt.Sprintf("env keys present: %v", mapKeys(info)))
	}
	summary["pg_container_name"] = pgContainer
	summary["db_name"] = dbName
	summary["db_user"] = dbUser

	pgVerOut, _, code, _ := runCmd(ctx, "docker",
		[]string{"exec", pgContainer,
			"psql", "-U", dbUser, "-d", dbName, "-A", "-t", "-c", "SHOW server_version_num;"})
	if code == 0 {
		raw := strings.TrimSpace(pgVerOut)
		// SHOW server_version_num devolve um inteiro tipo 160005 = 16.0.5
		if len(raw) >= 5 {
			n, _ := strconv.Atoi(raw)
			major := n / 10000
			summary["pg_version_num"] = raw
			summary["pg_version"] = strconv.Itoa(major)
		} else {
			summary["pg_version"] = raw
		}
	}

	baseQ := "SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM items), " +
		"(SELECT count(*) FROM triggers), (SELECT mandatory FROM dbversion);"
	baseOut, baseErr, code, _ := runCmd(ctx, "docker",
		[]string{"exec", pgContainer,
			"psql", "-U", dbUser, "-d", dbName, "-A", "-t", "-c", baseQ})
	if code != 0 {
		return failed(step, "baseline counts query failed", code,
			tail(baseErr+"\n"+baseOut, 1500))
	}
	parts := strings.Split(strings.TrimSpace(baseOut), "|")
	baseline := map[string]interface{}{}
	if len(parts) >= 4 {
		baseline["hosts"], _ = strconv.Atoi(parts[0])
		baseline["items"], _ = strconv.Atoi(parts[1])
		baseline["triggers"], _ = strconv.Atoi(parts[2])
		baseline["dbversion"] = parts[3]
	} else {
		return failed(step, "baseline query returned unexpected output", -1, baseOut)
	}
	summary["baseline_counts"] = baseline

	// (4) disco livre no snapshot dir (chamada nativa Go, não shell)
	freeGb, diskErr := diskFreeGb(snapshotDir())
	if diskErr != nil {
		// Não bloqueia — pode estar rodando antes do mkdir. Apenas avisa.
		summary["disk_check_skipped"] = diskErr.Error()
	} else {
		summary["disk_free_gb"] = freeGb
		summary["min_disk_free_gb"] = minDiskGb
		if freeGb < minDiskGb {
			return failed(step,
				fmt.Sprintf("insufficient disk: %.1fGB free, need %.1fGB", freeGb, minDiskGb),
				-1, "")
		}
	}

	return ok(step, 0, "preflight ok", "", summary)
}

// VALIDATE_COUNTS: roda count(*) novamente e compara com baseline_counts
// injetados no params pelo backend (vindos do preflight_report).
// Tolerance default = 0 (qualquer perda quebra). Operador pode override
// via params.tolerance_pct.
func (c *zabbixSyncCheck) stepValidateCounts(ctx context.Context, step *stepDTO) stepResult {
	pgContainer := strParam(step.Params, "pg_container_name", "")
	dbName := strParam(step.Params, "db_name", "")
	dbUser := strParam(step.Params, "db_user", "")
	tolPct := floatParam(step.Params, "tolerance_pct", 0)

	if pgContainer == "" || dbName == "" || dbUser == "" {
		info, err := dockerInspectEnv(ctx, step.TargetIdentifier)
		if err != nil {
			return failed(step, "inspect target", -1, err.Error())
		}
		if pgContainer == "" {
			pgContainer = info["DB_SERVER_HOST"]
			if pgContainer == "" { pgContainer = info["DB_HOST"] }
			if pgContainer != "" {
				if r := resolvePgContainer(ctx, pgContainer); r != "" { pgContainer = r }
			}
		}
		if dbName == "" {
			if v, ok := info["POSTGRES_DB"]; ok { dbName = v } else { dbName = info["DB_NAME"] }
		}
		if dbUser == "" {
			if v, ok := info["POSTGRES_USER"]; ok { dbUser = v } else { dbUser = info["DB_USER"] }
		}
	}
	q := "SELECT (SELECT count(*) FROM hosts), (SELECT count(*) FROM items), " +
		"(SELECT count(*) FROM triggers), (SELECT mandatory FROM dbversion);"
	args := []string{"exec", pgContainer,
		"psql", "-U", dbUser, "-d", dbName, "-A", "-t", "-c", q}
	stdout, stderr, code, err := runCmd(ctx, "docker", args)
	if err != nil || code != 0 {
		return failed(step, "psql validate", code, tail(stderr+"\n"+stdout, 1500))
	}
	line := strings.TrimSpace(stdout)
	parts := strings.Split(line, "|")
	summary := map[string]interface{}{"raw": line}
	if len(parts) >= 4 {
		hostsNow, _ := strconv.Atoi(parts[0])
		itemsNow, _ := strconv.Atoi(parts[1])
		trigNow, _ := strconv.Atoi(parts[2])
		summary["hosts"] = hostsNow
		summary["items"] = itemsNow
		summary["triggers"] = trigNow
		summary["dbversion"] = parts[3]

		// Compara contra baseline se disponível
		if baseline, ok := step.Params["baseline_counts"].(map[string]interface{}); ok {
			deltaErr := compareBaseline(baseline, hostsNow, itemsNow, trigNow, tolPct, summary)
			if deltaErr != "" {
				return failed(step, "count delta exceeds tolerance", -1, deltaErr)
			}
		}
	}
	return ok(step, 0, stdout, stderr, summary)
}

// ROLLBACK_RESTORE: restaura o estado anterior a partir do snapshot mais
// recente. Os params devem trazer (injetados pelo backend a partir do
// snapshot e do preflight_report):
//   snapshot_path        — arquivo .dump local
//   pg_container_name    — container PG onde restaurar
//   db_name, db_user     — credenciais PG
//   target_identifier    — container Zabbix server (DOCKER) ou unit (NATIVE)
//   old_image            — imagem original (do preflight container_image)
//
// Pipeline (DOCKER):
//   1. stop atual container Zabbix (pode ser o novo que falhou OU o velho ainda rodando)
//   2. docker exec PG psql -c "DROP DATABASE ... ; CREATE DATABASE ..."
//   3. docker cp <snapshot> pg:/tmp/snap.dump
//   4. docker exec PG pg_restore -d <db> --clean --if-exists --no-owner /tmp/snap.dump
//   5. inspect atual zabbix container → captura env/mounts
//   6. docker rm
//   7. docker run com OLD_IMAGE + mesmos env/mounts
//   8. (não fazemos WAIT aqui — caller pode anexar um WAIT_HEALTHY se quiser)
//
// Modo NATIVE: stub — operador faz restore manual no banco. Em V2 implementa
// systemctl stop + pg_restore local + apt install <old_pkg> + systemctl start.
func (c *zabbixSyncCheck) stepRollbackRestore(ctx context.Context, step *stepDTO) stepResult {
	if step.DeploymentMode != "DOCKER" {
		return failed(step,
			"ROLLBACK_RESTORE no modo NATIVE ainda não implementado — faça restore manual via pg_restore",
			-1, "snapshot_path="+strParam(step.Params, "snapshot_path", ""))
	}
	snapshotPath := strParam(step.Params, "snapshot_path", "")
	pgContainer := strParam(step.Params, "pg_container_name", "")
	dbName := strParam(step.Params, "db_name", "")
	dbUser := strParam(step.Params, "db_user", "")
	oldImage := strParam(step.Params, "old_image", "")
	zabbixContainer := step.TargetIdentifier

	if snapshotPath == "" || pgContainer == "" || dbName == "" || dbUser == "" {
		return failed(step,
			"missing required params (snapshot_path, pg_container_name, db_name, db_user)",
			-1, "")
	}
	if _, err := os.Stat(snapshotPath); err != nil {
		return failed(step, "snapshot file not accessible: "+snapshotPath, -1, err.Error())
	}

	logBuf := strings.Builder{}
	appendLog := func(stage, out, err string) {
		logBuf.WriteString("=== " + stage + " ===\n")
		if out != "" { logBuf.WriteString("[stdout] " + out + "\n") }
		if err != "" { logBuf.WriteString("[stderr] " + err + "\n") }
	}

	// (1) stop atual zabbix
	if zabbixContainer != "" {
		stdout, stderr, _, _ := runCmd(ctx, "docker", []string{"stop", zabbixContainer})
		appendLog("docker stop "+zabbixContainer, stdout, stderr)
	}

	// (2a) terminate connections — DROP DATABASE falha se houver sessões
	//     ativas. WITH (FORCE) seria mais limpo mas exige PG 13+. Usamos
	//     pg_terminate_backend pra max compat (funciona em PG 9.6+).
	termQ := fmt.Sprintf(
		"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "+
			"WHERE datname='%s' AND pid <> pg_backend_pid();", dbName)
	stdout, stderr, _, _ := runCmd(ctx, "docker",
		[]string{"exec", pgContainer, "psql", "-U", dbUser, "-d", "postgres",
			"-c", termQ})
	appendLog("terminate sessions", stdout, stderr)

	// (2b) drop database — separado pra não cair em transaction block do psql.
	dropOnly := "DROP DATABASE IF EXISTS " + dbName + ";"
	stdout, stderr, code, _ := runCmd(ctx, "docker",
		[]string{"exec", pgContainer, "psql", "-U", dbUser, "-d", "postgres",
			"-c", dropOnly})
	appendLog("drop db", stdout, stderr)
	if code != 0 {
		return failed(step, "DROP DATABASE failed", code, tail(logBuf.String(), 3500))
	}

	// (2c) create database — também separado.
	createOnly := "CREATE DATABASE " + dbName + " OWNER " + dbUser + ";"
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"exec", pgContainer, "psql", "-U", dbUser, "-d", "postgres",
			"-c", createOnly})
	appendLog("create db", stdout, stderr)
	if code != 0 {
		return failed(step, "CREATE DATABASE failed", code, tail(logBuf.String(), 3500))
	}

	// (3) docker cp snapshot → container
	tmpInContainer := "/tmp/ispwatch-rollback-" + step.StepID + ".dump"
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"cp", snapshotPath, pgContainer + ":" + tmpInContainer})
	appendLog("docker cp snapshot", stdout, stderr)
	if code != 0 {
		return failed(step, "copy snapshot into container failed", code, tail(logBuf.String(), 3500))
	}
	defer func() {
		_, _, _, _ = runCmd(ctx, "docker",
			[]string{"exec", pgContainer, "rm", "-f", tmpInContainer})
	}()

	// (4) pg_restore
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"exec", pgContainer,
			"pg_restore", "-U", dbUser, "-d", dbName,
			"--clean", "--if-exists", "--no-owner", "--no-acl",
			tmpInContainer})
	appendLog("pg_restore", stdout, stderr)
	if code != 0 {
		// pg_restore retorna exit=1 com warnings comuns (objetos já não existiam etc).
		// Aceitamos se stderr tem só warnings; falha real se "ERROR" presente.
		if strings.Contains(stderr, "ERROR:") {
			return failed(step, "pg_restore failed", code, tail(logBuf.String(), 3500))
		}
	}

	// (5)+(6)+(7) recria container com imagem antiga, se temos a imagem
	if oldImage != "" && zabbixContainer != "" {
		specJSON, errOut, code, _ := runCmd(ctx, "docker", []string{"inspect", zabbixContainer})
		if code == 0 {
			envs, mounts, networks, perr := parseInspect(specJSON)
			if perr == nil {
				_, _, _, _ = runCmd(ctx, "docker", []string{"rm", zabbixContainer})
				args := []string{"run", "-d", "--name", zabbixContainer,
					"--restart", "unless-stopped"}
				for _, e := range envs { args = append(args, "-e", e) }
				for _, m := range mounts { args = append(args, "-v", m) }
				for _, n := range networks { args = append(args, "--network", n) }
				args = append(args, oldImage)
				stdout, stderr, code, _ := runCmd(ctx, "docker", args)
				appendLog("docker run "+oldImage, stdout, stderr)
				if code != 0 {
					return failed(step, "docker run old image failed", code,
						tail(logBuf.String(), 3500))
				}
			}
		} else {
			appendLog("inspect skipped", "", tail(errOut, 200))
		}
	}

	return ok(step, 0, tail(logBuf.String(), 2000), "",
		map[string]interface{}{
			"snapshot_restored": snapshotPath,
			"old_image_started": oldImage != "",
		})
}

// PG_UPGRADE_DUMP_RESTORE: promove o PG entre majors (ex: 9.6 → 13). Roda
// ANTES dos saltos de Zabbix porque o novo Zabbix exige PG novo. Pipeline:
//
//   1. stop zabbix server (libera conexões)
//   2. pg_dump --format=custom do PG antigo → host file
//   3. stop + rename PG antigo pra <name>-pg<old>-pre-upgrade (preserva pra rollback)
//   4. docker pull postgres:<to_pg>-alpine
//   5. docker run novo container postgres com mesmo nome + creds + network do antigo
//      (volume novo, anonymous — operador pode override com pg_target_volume)
//   6. wait pg_isready
//   7. docker cp dump → new container + pg_restore --clean --if-exists
//   8. start zabbix server (DB_SERVER_HOST aponta pro mesmo hostname → resolve pro novo)
//
// Rollback manual: docker rename de volta + start old. Não há ROLLBACK_RESTORE
// para esse step (a recuperação envolve trocar imagens, não restaurar SQL).
//
// Params (injetados pelo backend a partir do preflight + planner):
//   from_pg, to_pg (major numbers)
//   pg_container_name (old PG container)
//   db_name, db_user
//   pg_target_image (opcional, default "postgres:<to_pg>-alpine")
func (c *zabbixSyncCheck) stepPgUpgradeDumpRestore(ctx context.Context, step *stepDTO) stepResult {
	if step.DeploymentMode != "DOCKER" {
		return failed(step,
			"PG_UPGRADE_DUMP_RESTORE no modo NATIVE ainda não implementado",
			-1, "")
	}
	fromPg := strParam(step.Params, "from_pg", "")
	toPg := strParam(step.Params, "to_pg", "")
	pgContainer := strParam(step.Params, "pg_container_name", "")
	dbName := strParam(step.Params, "db_name", "")
	dbUser := strParam(step.Params, "db_user", "")
	targetImage := strParam(step.Params, "pg_target_image", "")
	zabbixContainer := step.TargetIdentifier

	if fromPg == "" || toPg == "" || pgContainer == "" || dbName == "" || dbUser == "" {
		return failed(step,
			"missing required params (from_pg, to_pg, pg_container_name, db_name, db_user)",
			-1, "")
	}
	if targetImage == "" {
		targetImage = "postgres:" + toPg + "-alpine"
	}

	logBuf := strings.Builder{}
	appendLog := func(stage, out, errOut string) {
		logBuf.WriteString("=== " + stage + " ===\n")
		if out != "" { logBuf.WriteString("[stdout] " + tail(out, 600) + "\n") }
		if errOut != "" { logBuf.WriteString("[stderr] " + tail(errOut, 600) + "\n") }
	}

	// (1) stop zabbix server
	if zabbixContainer != "" {
		stdout, stderr, _, _ := runCmd(ctx, "docker", []string{"stop", zabbixContainer})
		appendLog("docker stop "+zabbixContainer, stdout, stderr)
	}

	// (2) dump from old PG → host. pg_dump dentro do container antigo (9.x).
	if err := os.MkdirAll(snapshotDir(), 0o755); err != nil {
		return failed(step, "mkdir snapshot dir", -1, err.Error())
	}
	dumpPath := filepath.Join(snapshotDir(), "pgupgrade-"+step.StepID+".dump")
	stdout, stderr, code, runErr := runWithRedirect(ctx, "docker",
		[]string{"exec", pgContainer,
			"pg_dump", "-Fc", "-Z", "1", "-U", dbUser, "-w", dbName},
		dumpPath)
	appendLog("pg_dump from old PG "+fromPg, stdout, stderr)
	if runErr != nil || code != 0 {
		os.Remove(dumpPath)
		return failed(step, "pg_dump from old PG failed", code, tail(logBuf.String(), 3500))
	}
	fi, _ := os.Stat(dumpPath)
	dumpBytes := int64(0)
	if fi != nil { dumpBytes = fi.Size() }

	// (3) captura network + env do PG antigo ANTES de renomear (precisamos
	// pra recriar com config compatível). dockerInspectEnv pega só env;
	// pra network usamos um inspect adicional.
	envInfo, err := dockerInspectEnv(ctx, pgContainer)
	if err != nil {
		return failed(step, "inspect old PG env", -1, err.Error())
	}
	pgPassword := envInfo["POSTGRES_PASSWORD"]
	if pgPassword == "" { pgPassword = "zabbix" } // fallback (postgres image requires this)
	netOut, _, _, _ := runCmd(ctx, "docker",
		[]string{"inspect", "--format",
			"{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}",
			pgContainer})
	networks := strings.Fields(strings.TrimSpace(netOut))

	// (4) stop + rename old PG. Status fica preservado pra rollback manual.
	stdout, stderr, code, _ = runCmd(ctx, "docker", []string{"stop", pgContainer})
	appendLog("stop old PG", stdout, stderr)
	archiveName := pgContainer + "-pg" + fromPg + "-preupgrade-" + step.StepID[:8]
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"rename", pgContainer, archiveName})
	appendLog("rename old PG → "+archiveName, stdout, stderr)
	if code != 0 {
		return failed(step, "rename old PG failed", code, tail(logBuf.String(), 3500))
	}
	// (rollback inline se algo falhar daqui pra frente: rename de volta)
	rollbackName := func() {
		runCmd(ctx, "docker", []string{"stop", pgContainer})
		runCmd(ctx, "docker", []string{"rm", pgContainer})
		runCmd(ctx, "docker", []string{"rename", archiveName, pgContainer})
		runCmd(ctx, "docker", []string{"start", pgContainer})
	}

	// (5) pull + run novo PG com mesmo nome
	stdout, stderr, code, _ = runCmd(ctx, "docker", []string{"pull", targetImage})
	appendLog("pull "+targetImage, stdout, stderr)
	if code != 0 {
		rollbackName()
		return failed(step, "pull "+targetImage, code, tail(logBuf.String(), 3500))
	}
	runArgs := []string{"run", "-d", "--name", pgContainer, "--restart", "unless-stopped",
		"-e", "POSTGRES_DB=" + dbName,
		"-e", "POSTGRES_USER=" + dbUser,
		"-e", "POSTGRES_PASSWORD=" + pgPassword}
	for _, n := range networks {
		if n != "" {
			runArgs = append(runArgs, "--network", n)
		}
	}
	runArgs = append(runArgs, targetImage)
	stdout, stderr, code, _ = runCmd(ctx, "docker", runArgs)
	appendLog("run new PG "+targetImage, stdout, stderr)
	if code != 0 {
		rollbackName()
		return failed(step, "run new PG failed", code, tail(logBuf.String(), 3500))
	}

	// (6) wait pg_isready (até 2 min)
	deadline := time.Now().Add(2 * time.Minute)
	ready := false
	for time.Now().Before(deadline) {
		_, _, c, _ := runCmd(ctx, "docker",
			[]string{"exec", pgContainer, "pg_isready", "-U", dbUser, "-d", dbName})
		if c == 0 { ready = true; break }
		time.Sleep(3 * time.Second)
	}
	if !ready {
		rollbackName()
		return failed(step, "new PG not ready after 2min", -1, tail(logBuf.String(), 3500))
	}
	appendLog("new PG ready", "", "")

	// (7) cp dump + pg_restore (pg_restore do PG novo lê dump do antigo OK
	// até 5 majors atrás, por compat documentada)
	tmpInside := "/tmp/pg-upgrade-" + step.StepID + ".dump"
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"cp", dumpPath, pgContainer + ":" + tmpInside})
	appendLog("docker cp dump", stdout, stderr)
	if code != 0 {
		rollbackName()
		return failed(step, "copy dump to new PG", code, tail(logBuf.String(), 3500))
	}
	// pg_restore sai com 1 ao ter warnings — não tratamos como falha exceto se "ERROR:"
	stdout, stderr, code, _ = runCmd(ctx, "docker",
		[]string{"exec", pgContainer,
			"pg_restore", "-U", dbUser, "-d", dbName,
			"--clean", "--if-exists", "--no-owner", "--no-acl",
			tmpInside})
	appendLog("pg_restore on new PG", stdout, stderr)
	if code != 0 && strings.Contains(stderr, "ERROR:") {
		rollbackName()
		return failed(step, "pg_restore failed", code, tail(logBuf.String(), 3500))
	}
	// cleanup dump file inside container
	_, _, _, _ = runCmd(ctx, "docker",
		[]string{"exec", pgContainer, "rm", "-f", tmpInside})

	// (8) start zabbix server (vai conectar ao novo PG via mesmo hostname)
	if zabbixContainer != "" {
		stdout, stderr, code, _ := runCmd(ctx, "docker",
			[]string{"start", zabbixContainer})
		appendLog("start "+zabbixContainer, stdout, stderr)
		if code != 0 {
			// PG novo está OK, mas zabbix não subiu — não rollback porque
			// dump→restore foi sucesso e operador pode subir manualmente.
			return failed(step,
				"new PG OK but failed to restart zabbix container; recover manually",
				code, tail(logBuf.String(), 3500))
		}
	}

	return ok(step, 0, tail(logBuf.String(), 2000), "",
		map[string]interface{}{
			"from_pg":               fromPg,
			"to_pg":                 toPg,
			"new_pg_image":          targetImage,
			"old_pg_container_kept": archiveName,
			"dump_bytes":            dumpBytes,
			"dump_path":             dumpPath,
		})
}

// STOP_SERVICE: systemctl stop <unit>. Requer root no host do agent.
func (c *zabbixSyncCheck) stepStopService(ctx context.Context, step *stepDTO) stepResult {
	unit := step.TargetIdentifier
	if unit == "" { unit = strParam(step.Params, "unit_name", "") }
	if unit == "" {
		return failed(step, "unit_name required", -1, "")
	}
	stdout, stderr, code, _ := runCmd(ctx, "systemctl", []string{"stop", unit})
	if code != 0 {
		return failed(step, "systemctl stop "+unit, code, tail(stderr+"\n"+stdout, 1500))
	}
	return ok(step, code, stdout, stderr, map[string]interface{}{"unit": unit, "action": "stop"})
}

// INSTALL_PACKAGE: adiciona repo oficial Zabbix + apt install zabbix-server-pgsql
// na versão alvo. Cobertura inicial: Debian/Ubuntu (detectado via /etc/os-release).
// RHEL/CentOS/Rocky/Alma fica pra V2.
func (c *zabbixSyncCheck) stepInstallPackage(ctx context.Context, step *stepDTO) stepResult {
	targetVer := strParam(step.Params, "target_version", "")
	pkgName := strParam(step.Params, "package", "zabbix-server-pgsql")
	if targetVer == "" {
		return failed(step, "target_version required", -1, "")
	}
	distroID, distroVer := detectDistro()
	logBuf := strings.Builder{}
	logBuf.WriteString("distro: " + distroID + " " + distroVer + "\n")

	switch distroID {
	case "ubuntu", "debian":
		// URL do release deb: usa os-release codename quando disponível
		codename := strings.ReplaceAll(distroVer, ".", "")
		releaseDeb := fmt.Sprintf(
			"https://repo.zabbix.com/zabbix/%s/%s/pool/main/z/zabbix-release/"+
				"zabbix-release_%s-1+%s%s_all.deb",
			targetVer, distroID, targetVer, distroID, codename)
		// (a) wget release deb
		tmpDeb := "/tmp/ispwatch-zabbix-release.deb"
		stdout, stderr, code, _ := runCmd(ctx, "wget", []string{"-q", "-O", tmpDeb, releaseDeb})
		logBuf.WriteString("wget release: " + tail(stderr, 200) + "\n")
		if code != 0 {
			return failed(step, "download release deb failed: "+releaseDeb, code,
				tail(logBuf.String()+stdout, 2500))
		}
		defer os.Remove(tmpDeb)

		// (b) dpkg -i + apt update + apt install
		stdout, stderr, code, _ = runCmd(ctx, "dpkg", []string{"-i", tmpDeb})
		logBuf.WriteString("dpkg -i: " + tail(stderr, 400) + "\n")
		if code != 0 {
			return failed(step, "dpkg install release failed", code, tail(logBuf.String(), 2500))
		}
		stdout, stderr, code, _ = runCmd(ctx, "apt-get", []string{"update"})
		logBuf.WriteString("apt update: " + tail(stderr, 200) + "\n")
		if code != 0 {
			return failed(step, "apt update failed", code, tail(logBuf.String(), 2500))
		}
		stdout, stderr, code, _ = runCmd(ctx, "apt-get",
			[]string{"install", "-y", "--allow-downgrades", pkgName})
		logBuf.WriteString("apt install " + pkgName + ": " + tail(stderr, 400) + "\n")
		if code != 0 {
			return failed(step, "apt install "+pkgName+" failed", code,
				tail(logBuf.String(), 3000))
		}
		return ok(step, 0, stdout, stderr,
			map[string]interface{}{"package": pkgName, "version_target": targetVer,
				"distro": distroID + " " + distroVer})
	default:
		return failed(step,
			"distro "+distroID+" não suportada (apenas debian/ubuntu na V1)",
			-1, tail(logBuf.String(), 1500))
	}
}

// START_SERVICE: systemctl start <unit> + verifica Active via systemctl is-active.
func (c *zabbixSyncCheck) stepStartService(ctx context.Context, step *stepDTO) stepResult {
	unit := step.TargetIdentifier
	if unit == "" { unit = strParam(step.Params, "unit_name", "") }
	if unit == "" {
		return failed(step, "unit_name required", -1, "")
	}
	stdout, stderr, code, _ := runCmd(ctx, "systemctl", []string{"start", unit})
	if code != 0 {
		return failed(step, "systemctl start "+unit, code, tail(stderr+"\n"+stdout, 1500))
	}
	// Confirma Active
	actOut, _, _, _ := runCmd(ctx, "systemctl", []string{"is-active", unit})
	active := strings.TrimSpace(actOut)
	if active != "active" {
		return failed(step, "service not active after start: "+active, -1, tail(stdout, 1000))
	}
	return ok(step, 0, stdout, stderr,
		map[string]interface{}{"unit": unit, "active": active, "action": "start"})
}

// detectDistro lê /etc/os-release pra retornar (ID, VERSION_ID). Fallback ("","").
func detectDistro() (string, string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil { return "", "" }
	var id, ver string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		}
		if strings.HasPrefix(line, "VERSION_CODENAME=") {
			ver = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), "\"")
		}
	}
	return id, ver
}

// compareBaseline retorna string vazia quando dentro da tolerance, ou uma
// mensagem com o delta de cada tabela quando excedeu.
func compareBaseline(baseline map[string]interface{}, hostsNow, itemsNow, trigNow int,
	tolPct float64, summary map[string]interface{}) string {
	hostsBase := intFromAny(baseline["hosts"])
	itemsBase := intFromAny(baseline["items"])
	trigBase := intFromAny(baseline["triggers"])
	deltas := map[string]map[string]interface{}{
		"hosts":    {"before": hostsBase, "after": hostsNow, "delta": hostsNow - hostsBase},
		"items":    {"before": itemsBase, "after": itemsNow, "delta": itemsNow - itemsBase},
		"triggers": {"before": trigBase,  "after": trigNow,  "delta": trigNow - trigBase},
	}
	summary["deltas"] = deltas

	check := func(name string, before, after int) string {
		if before == 0 {
			if after < 0 { return name + " went negative" }
			return ""
		}
		if after < before {
			lostPct := float64(before-after) / float64(before) * 100
			if lostPct > tolPct {
				return fmt.Sprintf("%s lost %d rows (%.2f%% > tol %.2f%%)",
					name, before-after, lostPct, tolPct)
			}
		}
		return ""
	}
	var msgs []string
	for _, m := range []string{
		check("hosts", hostsBase, hostsNow),
		check("items", itemsBase, itemsNow),
		check("triggers", trigBase, trigNow),
	} {
		if m != "" { msgs = append(msgs, m) }
	}
	if len(msgs) > 0 {
		return strings.Join(msgs, "; ")
	}
	return ""
}

func intFromAny(v interface{}) int {
	switch t := v.(type) {
	case int: return t
	case int64: return int(t)
	case float64: return int(t)
	case string: n, _ := strconv.Atoi(t); return n
	}
	return 0
}

// resolvePgContainer recebe um hostname/service name (ex: "zbx-db") e
// procura o container Docker correspondente. Tenta:
//   1. nome exato
//   2. docker ps --filter name=*<hint>* — pega o primeiro
func resolvePgContainer(ctx context.Context, hint string) string {
	if hint == "" { return "" }
	stdout, _, code, _ := runCmd(ctx, "docker",
		[]string{"ps", "--format", "{{.Names}}", "--filter", "name=" + hint})
	if code != 0 { return "" }
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" { continue }
		return line
	}
	return ""
}

func diskFreeGb(path string) (float64, error) {
	if path == "" { return 0, fmt.Errorf("empty path") }
	if _, err := os.Stat(path); err != nil {
		if errs := os.MkdirAll(path, 0o755); errs != nil {
			return 0, err
		}
	}
	stat, err := osStatfs(path)
	if err != nil { return 0, err }
	freeBytes := float64(stat.Bavail) * float64(stat.Bsize)
	return freeBytes / 1024 / 1024 / 1024, nil
}

func mapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m { out = append(out, k) }
	return out
}

func floatParam(p map[string]interface{}, key string, def float64) float64 {
	if v, ok := p[key]; ok {
		switch t := v.(type) {
		case float64: return t
		case int: return float64(t)
		case string:
			f, err := strconv.ParseFloat(t, 64)
			if err == nil { return f }
		}
	}
	return def
}

// ---- helpers ----

// runCmd executa cmd com args, captura stdout/stderr, retorna exit code.
// Erros de exec.Start (cmd não encontrado) viram err != nil; cmd que
// rodou e saiu com não-zero retorna err == nil + exitCode != 0.
func runCmd(ctx context.Context, name string, args []string) (string, string, int, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", err.Error(), -1, err
	}
	err := cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
			err = nil
		} else {
			code = -1
		}
	}
	return outBuf.String(), errBuf.String(), code, err
}

// runWithRedirect roda cmd com stdout salvo em arquivo (pra pg_dump).
func runWithRedirect(ctx context.Context, name string, args []string, outFile string) (string, string, int, error) {
	f, err := os.Create(outFile)
	if err != nil {
		return "", "", -1, err
	}
	defer f.Close()
	cmd := exec.CommandContext(ctx, name, args...)
	var errBuf bytes.Buffer
	cmd.Stdout = f
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		return "", err.Error(), -1, err
	}
	err = cmd.Wait()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
			err = nil
		} else {
			code = -1
		}
	}
	return "[stdout redirected to " + outFile + "]", errBuf.String(), code, err
}

// dockerInspectEnv extrai env vars do container num map. Usa Go template
// pra evitar parse JSON pesado.
func dockerInspectEnv(ctx context.Context, container string) (map[string]string, error) {
	stdout, stderr, code, err := runCmd(ctx, "docker", []string{
		"inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", container,
	})
	if err != nil || code != 0 {
		return nil, fmt.Errorf("inspect %s: %s", container, tail(stderr, 200))
	}
	m := make(map[string]string)
	for _, line := range strings.Split(stdout, "\n") {
		if i := strings.IndexByte(line, '='); i > 0 {
			m[line[:i]] = line[i+1:]
		}
	}
	return m, nil
}

// parseInspect extrai env, mounts (host:container[:ro]), networks de uma
// inspect raw JSON. Usado pra recriar o container com a imagem nova.
func parseInspect(jsonRaw string) (envs, mounts, networks []string, err error) {
	var arr []struct {
		Config struct {
			Env []string `json:"Env"`
		} `json:"Config"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			Mode        string `json:"Mode"`
		} `json:"Mounts"`
		NetworkSettings struct {
			Networks map[string]interface{} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal([]byte(jsonRaw), &arr); err != nil {
		return nil, nil, nil, err
	}
	if len(arr) == 0 {
		return nil, nil, nil, fmt.Errorf("empty inspect")
	}
	c := arr[0]
	for _, m := range c.Mounts {
		// Type=volume → -v <name>:<dest>; Type=bind → -v <src>:<dest>
		spec := m.Source + ":" + m.Destination
		if m.Mode != "" && m.Mode != "rw" {
			spec += ":" + m.Mode
		}
		mounts = append(mounts, spec)
	}
	for n := range c.NetworkSettings.Networks {
		networks = append(networks, n)
	}
	return c.Config.Env, mounts, networks, nil
}

func strParam(p map[string]interface{}, key, def string) string {
	if v, ok := p[key]; ok {
		if s, ok2 := v.(string); ok2 {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return def
}

func intParam(p map[string]interface{}, key string, def int) int {
	if v, ok := p[key]; ok {
		switch t := v.(type) {
		case float64:
			return int(t)
		case int:
			return t
		case string:
			if n, err := strconv.Atoi(t); err == nil {
				return n
			}
		}
	}
	return def
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func ok(step *stepDTO, code int, stdout, stderr string, summary map[string]interface{}) stepResult {
	c := code
	return stepResult{
		Status: "succeeded",
		ExitCode: &c,
		StdoutTail: tail(stdout, 2000),
		StderrTail: tail(stderr, 1000),
		ResultSummary: summary,
	}
}

func failed(step *stepDTO, msg string, code int, detail string) stepResult {
	c := code
	stderr := msg
	if detail != "" {
		stderr += "\n" + detail
	}
	return stepResult{
		Status: "failed",
		ExitCode: &c,
		StderrTail: tail(stderr, 3500),
		ResultSummary: map[string]interface{}{"error": msg},
	}
}

func ptrInt(v int) *int { return &v }
