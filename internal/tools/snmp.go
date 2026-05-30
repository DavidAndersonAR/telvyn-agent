package tools

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ispwatch/collector/internal/snmp"
)

// SNMP executors. Two flavours:
//
//   snmp.get  — fetch one or more scalar OIDs in a single packet
//   snmp.walk — BulkWalk a subtree (interface table, host resources, ...)
//
// Both honour the same args envelope:
//
//   target           string   required  "host" or "host:port" (default :161)
//   community        string   required v2c  SNMPv2c read-only community
//   timeout_seconds  number   optional  per-request UDP timeout, default 5
//
// SNMPv3 (Plan 03-01) adiciona os campos opcionais abaixo. Quando version="v3"
// community e ignorado.
//
//   version          string   "v2c" (default) ou "v3"
//   v3_user          string   required when version=v3
//   v3_auth_proto    string   NoAuth|MD5|SHA|SHA224|SHA256|SHA384|SHA512
//   v3_auth_pass     string   passphrase (sem default)
//   v3_priv_proto    string   NoPriv|DES|AES|AES192|AES256|AES192C|AES256C
//   v3_priv_pass     string   passphrase (sem default)
//   v3_context       string   contextName opcional (engineId discovery cobre o resto)
//
// snmp.get takes:
//   oids  []string  required  list of dotted OIDs
//   names []string  optional  parallel array of friendly metric names; if
//                             missing or short, falls back to "snmp:<oid>"
//
// snmp.walk takes:
//   root         string  required  table root OID
//   metric_name  string  optional  friendly name for emitted points;
//                                  default "snmp:<root>"
//
// Both executors return result.metrics = [{name, value, tags?, ...}, ...]
// which the agent's job scheduler converts to wire Metrics. Non-numeric PDUs
// (OctetString, ObjectIdentifier) are skipped — those don't fit a TSDB row.

const defaultSnmpTimeout = 5 * time.Second

// SnmpGet runs an SNMP GET against `target` for the listed `oids`. Versao
// padrao e v2c; quando args["version"]=="v3" o executor monta um Client
// v3 (USM auth+priv) consumindo os campos v3_*.
type SnmpGet struct{}

func (SnmpGet) Name() string { return "snmp.get" }

func (SnmpGet) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	p, err := paramsFromArgs(args)
	if err != nil {
		return nil, err
	}
	oids, err := requireStringSlice(args, "oids")
	if err != nil {
		return nil, err
	}
	names := optStringSlice(args, "names")

	c, err := snmp.NewClient(p)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	pdus, err := c.Get(ctx, oids)
	if err != nil {
		return nil, err
	}

	metrics := make([]any, 0, len(pdus))
	values := make(map[string]any, len(pdus))
	for i, pdu := range pdus {
		name := snmpDefaultName(pdu.Name)
		if i < len(names) && names[i] != "" {
			name = names[i]
		}
		if val, ok := snmp.PduFloat(pdu); ok {
			metrics = append(metrics, map[string]any{
				"name": name, "value": val, "source": "snmp",
				"tags": map[string]any{"oid": pdu.Name},
			})
			values[pdu.Name] = val
		} else if s := pduString(pdu); s != "" {
			values[pdu.Name] = s
		}
	}
	result := map[string]any{"metrics": metrics, "count": float64(len(metrics))}
	if len(values) > 0 {
		result["values"] = values
	}
	return result, nil
}

// SnmpWalk runs an SNMP BulkWalk under `root` and emits one point per leaf.
// Suporta v2c (default) e v3 via mesmos campos opcionais do SnmpGet.
type SnmpWalk struct{}

func (SnmpWalk) Name() string { return "snmp.walk" }

func (SnmpWalk) Execute(ctx context.Context, args map[string]any) (map[string]any, error) {
	p, err := paramsFromArgs(args)
	if err != nil {
		return nil, err
	}
	root, err := requireString(args, "root")
	if err != nil {
		return nil, err
	}
	metricName := optString(args, "metric_name", snmpDefaultName(root))

	c, err := snmp.NewClient(p)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	metrics := make([]any, 0, 16)
	err = c.BulkWalk(ctx, root, func(pdu gosnmp.SnmpPDU) error {
		val, ok := snmp.PduFloat(pdu)
		if !ok {
			return nil
		}
		metrics = append(metrics, map[string]any{
			"name":   metricName,
			"value":  val,
			"source": "snmp",
			"tags": map[string]any{
				"oid":   pdu.Name,
				"index": indexBelow(pdu.Name, root),
			},
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"metrics": metrics, "count": float64(len(metrics))}, nil
}

// paramsFromArgs constroi snmp.Params a partir do envelope de args do executor.
// Validacoes: target obrigatorio; community obrigatorio em v2c; v3_user
// obrigatorio em v3. Demais campos v3 sao opcionais (Client default eh
// NoAuth/NoPriv quando nao informado).
func paramsFromArgs(args map[string]any) (snmp.Params, error) {
	target, err := requireString(args, "target")
	if err != nil {
		return snmp.Params{}, err
	}

	version := optString(args, "version", "v2c")
	timeoutSec := optInt(args, "timeout_seconds", int(defaultSnmpTimeout.Seconds()))
	if timeoutSec <= 0 {
		timeoutSec = int(defaultSnmpTimeout.Seconds())
	}
	timeout := time.Duration(timeoutSec) * time.Second

	p := snmp.Params{
		Target:  target,
		Version: version,
		Timeout: timeout,
	}

	switch strings.ToLower(strings.TrimSpace(version)) {
	case "v2c", "":
		community, err := requireString(args, "community")
		if err != nil {
			return snmp.Params{}, err
		}
		p.Community = community
	case "v3":
		user, err := requireString(args, "v3_user")
		if err != nil {
			return snmp.Params{}, err
		}
		p.V3User = user
		p.V3AuthProto = optString(args, "v3_auth_proto", "NoAuth")
		p.V3AuthPass = optString(args, "v3_auth_pass", "")
		p.V3PrivProto = optString(args, "v3_priv_proto", "NoPriv")
		p.V3PrivPass = optString(args, "v3_priv_pass", "")
		p.V3ContextName = optString(args, "v3_context", "")
	default:
		return snmp.Params{}, fmt.Errorf("snmp: version invalida %q (esperado v2c ou v3)", version)
	}

	return p, nil
}

// snmpDefaultName turns a raw OID into "snmp:<oid>" for unnamed columns.
func snmpDefaultName(oid string) string { return "snmp:" + oid }

// indexBelow returns the suffix of `oid` after the trailing dot of `root`,
// or "" if oid is not strictly under root. Used so walk results carry the
// row index ("3" for `1.3.6.1.2.1.2.2.1.10.3` under `...10`).
func indexBelow(oid, root string) string {
	if len(oid) > len(root)+1 && oid[:len(root)] == root && oid[len(root)] == '.' {
		return oid[len(root)+1:]
	}
	return ""
}

// requireStringSlice / optStringSlice — small helpers used by snmp.get.
// structpb arrays come in as []any, so we walk and assert per element.
func requireStringSlice(args map[string]any, key string) ([]string, error) {
	v, ok := args[key]
	if !ok {
		return nil, fmt.Errorf("missing required arg %q", key)
	}
	raw, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("arg %q must be an array", key)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("arg %q must not be empty", key)
	}
	out := make([]string, 0, len(raw))
	for i, x := range raw {
		s, ok := x.(string)
		if !ok || s == "" {
			return nil, fmt.Errorf("arg %q[%d] must be a non-empty string", key, i)
		}
		out = append(out, s)
	}
	return out, nil
}

func optStringSlice(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok {
		return nil
	}
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func optString(args map[string]any, key, def string) string {
	v, ok := args[key]
	if !ok {
		return def
	}
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
