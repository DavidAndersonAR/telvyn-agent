// postgres_queries.go — check "postgres.queries": estatística POR CONSULTA lida
// do próprio banco, via pg_stat_statements. É o que o pgAdmin e o Database
// Monitoring do Datadog mostram, e o que o rastreamento das aplicações NÃO
// enxerga: psql de um DBA, cron, ferramenta de BI, migração.
//
// # POR QUE NÃO EMITE SPAN
//
// Existia uma versão anterior disto (na cópia antiga do agente) que fabricava um
// span por consulta: carimbava `agora` como instante de execução e usava a média
// histórica como duração. Isso descreve um evento que nunca aconteceu — span diz
// "rodou neste instante, por este tempo", e pg_stat_statements diz "rodou 40 mil
// vezes desde o último zeramento, com média de 3 ms". Além de errado, enchia o
// armazenamento de rastros, que é o que mais cresce.
//
// Aqui vai como o que é: estatística agregada, por um canal próprio.
//
// # DELTA, NÃO ACUMULADO
//
// pg_stat_statements conta desde o último zeramento. "1,4 milhão de chamadas"
// não diz nada sobre agora. Guardamos a leitura anterior em memória e mandamos a
// DIFERENÇA: "nos últimos 60s, rodou 120 vezes, média de 3,1 ms". A primeira
// leitura só estabelece a base e não manda nada — não há com o que comparar.
//
// Se um contador DIMINUI, o banco foi zerado (ou a entrada foi despejada da
// tabela, que tem tamanho fixo): descartamos aquele intervalo e recomeçamos a
// base. Mandar a diferença negativa viraria um pico absurdo na tela.
package checks

import (
	"context"
	"fmt"
	"log"
	"time"

	collectorv1 "github.com/ispwatch/collector/proto/v1"
	"github.com/jackc/pgx/v5"
)

const (
	defaultPostgresQueriesInterval = 60 * time.Second

	// Quantas consultas mandamos por coleta. O topo por tempo gasto no
	// intervalo — é onde está o problema, não na cauda.
	postgresQueriesTopN = 50

	// Teto do texto da consulta. pg_stat_statements já normaliza (troca
	// literais por $1), mas um IN com mil itens ainda vem gigante.
	postgresQueryTextMax = 4096
)

// SQL: tudo que precisamos pra calcular delta. queryid é a chave estável entre
// leituras — o texto pode ser truncado pelo servidor e não serve de chave.
//
// total_exec_time/mean_exec_time existem no PG 13+; em PG 12 chamavam
// total_time/mean_time. Não tratamos o 12: ele saiu de suporte em 2024.
const sqlPgStatStatements = `
	SELECT queryid::text, query, calls, total_exec_time, rows
	  FROM pg_stat_statements
	 WHERE queryid IS NOT NULL
	 ORDER BY total_exec_time DESC
	 LIMIT $1`

// pgxQueryPool é o subset que este check consome. Interface PRÓPRIA porque o
// pgxPool do postgres.server só expõe QueryRow (uma linha) e aqui precisamos
// varrer a tabela inteira. Existir separada também dá um ponto de injeção pro
// teste, sem abrir conexão nenhuma.
type pgxQueryPool interface {
	Ping(ctx context.Context) error
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Close()
}

// leitura de uma consulta num instante.
type querySnapshot struct {
	calls   int64
	totalMs float64
	rows    int64
}

// QueryStat é o que sai daqui: já é DIFERENÇA, referente ao intervalo.
type QueryStat struct {
	QueryID string  `json:"query_id"`
	Text    string  `json:"text"`
	Calls   int64   `json:"calls"`
	TotalMs float64 `json:"total_ms"`
	MeanMs  float64 `json:"mean_ms"`
	Rows    int64   `json:"rows"`
}

// QueryStatsSink recebe os lotes. Ligado no main pro IngestExporter; nil em
// teste, e aí o check roda sem mandar nada.
type QueryStatsSink func(dbServer string, stats []QueryStat)

var queryStatsSink QueryStatsSink

// SetQueryStatsSink liga o canal de saída. Chamado uma vez, no boot.
func SetQueryStatsSink(s QueryStatsSink) { queryStatsSink = s }

type postgresQueries struct {
	id         string
	interval   time.Duration
	staticTags map[string]string
	dbServer   string
	// Mesma interface do postgres.server: o teste injeta um pool falso que não
	// abre conexão nenhuma.
	pool pgxQueryPool

	// leitura anterior, pra calcular a diferença. Vazio = primeira coleta.
	anterior map[string]querySnapshot
}

func init() {
	Default.Register("postgres.queries", newPostgresQueriesCheck)
}

func newPostgresQueriesCheck(cfg *collectorv1.CheckConfig) (Check, error) {
	params := cfg.GetParams()
	dsn := params["dsn"]
	if dsn == "" {
		return nil, fmt.Errorf("postgres.queries: param 'dsn' obrigatório")
	}

	bruto, err := defaultPgxPoolFactory(context.Background(), dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres.queries: %w", err)
	}
	// O factory devolve a interface enxuta do postgres.server, mas o valor
	// concreto é *pgxpool.Pool, que tem Query. A asserção é o preço de reusar
	// a mesma construção de pool (MaxConns/MinConns) em vez de duplicá-la.
	pool, ok := bruto.(pgxQueryPool)
	if !ok {
		bruto.Close()
		return nil, fmt.Errorf("postgres.queries: pool sem suporte a Query")
	}
	// Ping antes de aceitar o check: falhar aqui devolve o motivo real
	// (senha, rede) no log do agente, em vez de silêncio a cada minuto.
	pingCtx, cancel := context.WithTimeout(context.Background(), postgresPingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("postgres.queries: unreachable: %w", err)
	}

	interval := cfg.GetInterval().AsDuration()
	if interval <= 0 {
		interval = defaultPostgresQueriesInterval
	}
	id := cfg.GetCheckId()
	if id == "" {
		id = "postgres.queries-" + cfg.GetHostId()
	}

	// db_server vem das tags do check (o backend carimba no cadastro). É a
	// chave que amarra a estatística ao banco certo na tela — sem ela, dois
	// bancos do mesmo agente se misturariam.
	tags := make(map[string]string, len(cfg.GetStaticTags()))
	for k, v := range cfg.GetStaticTags() {
		tags[k] = v
	}
	server := tags["db_server"]
	if server == "" {
		server = tags["db_label"]
	}

	return &postgresQueries{
		id:         id,
		interval:   interval,
		staticTags: tags,
		dbServer:   server,
		pool:       pool,
		anterior:   make(map[string]querySnapshot),
	}, nil
}

func (c *postgresQueries) ID() string              { return c.id }
func (c *postgresQueries) Interval() time.Duration { return c.interval }
func (c *postgresQueries) Tags() map[string]string { return c.staticTags }

func (c *postgresQueries) Close() error {
	if c.pool != nil {
		c.pool.Close()
	}
	return nil
}

// Run lê pg_stat_statements, calcula a diferença contra a leitura anterior e
// entrega o lote. NÃO devolve métrica: texto de consulta é cardinalidade alta
// demais pra um armazenamento de séries temporais — viraria uma série por
// consulta, para sempre.
func (c *postgresQueries) Run(ctx context.Context) ([]*collectorv1.Metric, error) {
	rows, err := c.pool.Query(ctx, sqlPgStatStatements, postgresQueriesTopN)
	if err != nil {
		// A extensão pode não estar instalada. Não é falha do agente: é
		// configuração do banco do cliente, e a mensagem tem que dizer isso.
		return nil, fmt.Errorf("postgres.queries: %w "+
			"(a extensão pg_stat_statements precisa estar em shared_preload_libraries "+
			"e criada com CREATE EXTENSION)", err)
	}
	defer rows.Close()

	atual := make(map[string]querySnapshot, postgresQueriesTopN)
	textos := make(map[string]string, postgresQueriesTopN)
	for rows.Next() {
		var qid, texto string
		var calls, nrows int64
		var totalMs float64
		if err := rows.Scan(&qid, &texto, &calls, &totalMs, &nrows); err != nil {
			continue
		}
		if len(texto) > postgresQueryTextMax {
			texto = texto[:postgresQueryTextMax]
		}
		atual[qid] = querySnapshot{calls: calls, totalMs: totalMs, rows: nrows}
		textos[qid] = texto
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres.queries: leitura: %w", err)
	}

	primeira := len(c.anterior) == 0
	saida := c.diferenca(atual, textos)
	c.anterior = atual

	// Primeira coleta só estabelece a base: não há intervalo anterior, então
	// qualquer número aqui seria "desde que o banco subiu" disfarçado de "no
	// último minuto".
	if primeira {
		log.Printf("postgres.queries: base estabelecida (%d consultas) para %s", len(atual), c.dbServer)
		return nil, nil
	}
	if len(saida) > 0 && queryStatsSink != nil {
		queryStatsSink(c.dbServer, saida)
	}
	return nil, nil
}

// diferenca compara com a leitura anterior. Só sai o que rodou NO INTERVALO.
func (c *postgresQueries) diferenca(atual map[string]querySnapshot, textos map[string]string) []QueryStat {
	out := make([]QueryStat, 0, len(atual))
	for qid, agora := range atual {
		antes, tinha := c.anterior[qid]
		if !tinha {
			// Consulta nova nesta janela: o acumulado dela É o do intervalo.
			antes = querySnapshot{}
		}
		dCalls := agora.calls - antes.calls
		dTotal := agora.totalMs - antes.totalMs
		dRows := agora.rows - antes.rows

		// Contador que anda pra trás = banco zerado ou entrada despejada da
		// tabela (ela tem tamanho fixo). Descarta o intervalo em vez de
		// publicar um número negativo ou um pico falso.
		if dCalls < 0 || dTotal < 0 {
			continue
		}
		if dCalls == 0 {
			continue // não rodou nesta janela: não é notícia
		}
		if dRows < 0 {
			dRows = 0
		}
		out = append(out, QueryStat{
			QueryID: qid,
			Text:    textos[qid],
			Calls:   dCalls,
			TotalMs: dTotal,
			MeanMs:  dTotal / float64(dCalls),
			Rows:    dRows,
		})
	}
	return out
}
