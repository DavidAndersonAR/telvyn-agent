package snmp

import (
	"context"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// WalkTable percorre uma tabela SNMP e retorna as PDUs organizadas como
// mapa de duas dimensoes: rowIndex -> colOID -> PDU. Conveniencia para o
// profile loader (Plan 03-02) e para callers que pensam em termos de
// linhas+colunas em vez de stream de PDUs.
//
// Convencao SMI: entries de uma tabela tem a forma <tableRoot>.1.<col>.<rowIndex>
// onde rowIndex pode ser composto (multiplos componentes separados por ponto,
// e.g. IPv4 na ipAddrTable). WalkTable extrai col e rowIndex via prefix match
// contra <tableRoot>.1.
//
// colOID retornado e o OID completo da coluna ate antes do rowIndex, com leading
// dot ('.1.3.6.1.2.1.2.2.1.10'). PDUs fora de tableRoot.1.* sao puladas.
//
// O ctx pode ser nil — nesse caso BulkWalk decide o que fazer.
func WalkTable(ctx context.Context, c *Client, tableRoot string) (map[string]map[string]gosnmp.SnmpPDU, error) {
	root := strings.TrimPrefix(strings.TrimSpace(tableRoot), ".")
	entryPrefix := root + ".1."

	out := make(map[string]map[string]gosnmp.SnmpPDU)

	walkCtx := ctx
	if walkCtx == nil {
		walkCtx = context.Background()
	}

	err := c.BulkWalk(walkCtx, root, func(p gosnmp.SnmpPDU) error {
		if err := walkCtx.Err(); err != nil {
			return err
		}
		name := strings.TrimPrefix(p.Name, ".")
		if !strings.HasPrefix(name, entryPrefix) {
			// PDU fora da tabela — gosnmp eventualmente entrega coisas
			// adjacentes; preferimos pular silenciosamente.
			return nil
		}
		suffix := name[len(entryPrefix):]
		if suffix == "" {
			return nil
		}
		// suffix = "<col>.<rowIndex...>". O primeiro componente e col, o resto
		// e o rowIndex (pode ser composto: '10.0.0.1').
		dot := strings.Index(suffix, ".")
		if dot < 0 {
			// Coluna sem rowIndex (improvavel mas possivel se o agent retornar
			// o proprio entry root) — pular para nao gerar key vazia.
			return nil
		}
		col := suffix[:dot]
		rowIndex := suffix[dot+1:]
		if col == "" || rowIndex == "" {
			return nil
		}
		colOID := "." + entryPrefix + col

		row, ok := out[rowIndex]
		if !ok {
			row = make(map[string]gosnmp.SnmpPDU)
			out[rowIndex] = row
		}
		row[colOID] = p
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
