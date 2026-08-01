package checks

import "testing"

// atalho: monta o check só com o estado que a diferença usa (sem pool, sem rede).
func comAnterior(ant map[string]querySnapshot) *postgresQueries {
	return &postgresQueries{dbServer: "pg.teste", anterior: ant}
}

func porID(s []QueryStat) map[string]QueryStat {
	m := make(map[string]QueryStat, len(s))
	for _, q := range s {
		m[q.QueryID] = q
	}
	return m
}

// O ponto todo do check: pg_stat_statements conta desde o zeramento. O que sai
// daqui tem que ser o que rodou NO INTERVALO.
func TestDiferencaEhDoIntervaloNaoDoAcumulado(t *testing.T) {
	c := comAnterior(map[string]querySnapshot{
		"1": {calls: 1_400_000, totalMs: 4_200_000, rows: 9_000_000},
	})
	got := porID(c.diferenca(
		map[string]querySnapshot{"1": {calls: 1_400_120, totalMs: 4_200_372, rows: 9_000_600}},
		map[string]string{"1": "SELECT * FROM x WHERE id = $1"},
	))

	q, ok := got["1"]
	if !ok {
		t.Fatal("consulta sumiu")
	}
	if q.Calls != 120 {
		t.Errorf("calls = %d, esperava 120 (o delta, não 1.400.120)", q.Calls)
	}
	if q.TotalMs != 372 {
		t.Errorf("total = %v, esperava 372", q.TotalMs)
	}
	if q.MeanMs != 3.1 {
		t.Errorf("média = %v, esperava 3,1 (372/120)", q.MeanMs)
	}
	if q.Rows != 600 {
		t.Errorf("rows = %d, esperava 600", q.Rows)
	}
}

// Zeramento do banco (ou despejo da entrada) faz o contador andar pra trás.
// Publicar isso viraria um número negativo ou, pior, um pico gigante quando ele
// voltasse a subir.
func TestContadorQueAndaProTrasEhDescartado(t *testing.T) {
	c := comAnterior(map[string]querySnapshot{
		"1": {calls: 5000, totalMs: 15000},
		"2": {calls: 100, totalMs: 300},
	})
	got := c.diferenca(map[string]querySnapshot{
		"1": {calls: 12, totalMs: 30},   // zerado: 5000 -> 12
		"2": {calls: 140, totalMs: 420}, // normal
	}, map[string]string{"1": "a", "2": "b"})

	if len(got) != 1 || got[0].QueryID != "2" {
		t.Fatalf("esperava só a consulta 2, veio %+v", got)
	}
}

// Consulta que não rodou no intervalo não é notícia — senão a tela enche de
// linha com zero e a que importa some no meio.
func TestConsultaParadaNaoSai(t *testing.T) {
	c := comAnterior(map[string]querySnapshot{"1": {calls: 50, totalMs: 100}})
	got := c.diferenca(
		map[string]querySnapshot{"1": {calls: 50, totalMs: 100}},
		map[string]string{"1": "a"},
	)
	if len(got) != 0 {
		t.Errorf("esperava nada, veio %+v", got)
	}
}

// Consulta que apareceu agora: não havia leitura anterior, então o acumulado
// dela É o do intervalo.
func TestConsultaNovaContaInteira(t *testing.T) {
	c := comAnterior(map[string]querySnapshot{"1": {calls: 10, totalMs: 20}})
	got := porID(c.diferenca(
		map[string]querySnapshot{
			"1": {calls: 10, totalMs: 20},
			"2": {calls: 7, totalMs: 21},
		},
		map[string]string{"1": "a", "2": "b"},
	))
	q, ok := got["2"]
	if !ok {
		t.Fatal("consulta nova não saiu")
	}
	if q.Calls != 7 || q.MeanMs != 3 {
		t.Errorf("esperava 7 chamadas e média 3, veio %d e %v", q.Calls, q.MeanMs)
	}
}

// rows pode andar pra trás sozinho sem que calls ande (planos diferentes);
// não descarta a linha inteira por isso, só piso em zero.
func TestRowsNegativoViraZeroSemDescartar(t *testing.T) {
	c := comAnterior(map[string]querySnapshot{"1": {calls: 10, totalMs: 20, rows: 500}})
	got := porID(c.diferenca(
		map[string]querySnapshot{"1": {calls: 15, totalMs: 35, rows: 400}},
		map[string]string{"1": "a"},
	))
	q, ok := got["1"]
	if !ok {
		t.Fatal("linha foi descartada por causa do rows")
	}
	if q.Rows != 0 {
		t.Errorf("rows = %d, esperava 0", q.Rows)
	}
	if q.Calls != 5 {
		t.Errorf("calls = %d, esperava 5", q.Calls)
	}
}

// O buraco que os testes acima deixaram passar: eles injetam um pool falso, e o
// que quebrou em produção foi a CONSTRUÇÃO — o wrapper que o factory devolve não
// tinha Query, então a asserção de tipo falhava e o check nunca rodava.
//
// Não abre conexão: só checa que o tipo concreto satisfaz a interface. É uma
// verificação de compilação disfarçada de teste, e é exatamente o que faltava.
func TestWrapperRealSatisfazPgxQueryPool(t *testing.T) {
	var _ pgxQueryPool = (*realPgxPool)(nil)
}
