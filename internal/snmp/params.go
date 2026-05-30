// params.go — helper para construir snmp.Params a partir do CheckConfig.params
// (map<string,string>) usado pelo check snmp.generic. tools/snmp.go nao usa este
// helper porque o envelope la e map[string]any (structpb); checks usam o
// map de strings nativo do CheckConfig.

package snmp

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ParamsFromMap monta snmp.Params a partir do map de params do CheckConfig.
// Validacoes:
//   - target obrigatorio
//   - version default "v2c"; em v2c exige community; em v3 exige v3_user
//   - timeout_seconds default 5
//
// Demais campos v3 sao opcionais — Client cai em NoAuth/NoPriv quando vazios.
func ParamsFromMap(params map[string]string) (Params, error) {
	target := strings.TrimSpace(params["target"])
	if target == "" {
		return Params{}, fmt.Errorf("snmp: missing param 'target'")
	}

	version := strings.ToLower(strings.TrimSpace(params["version"]))
	if version == "" {
		version = "v2c"
	}

	timeoutSec := defaultTimeoutSeconds
	if raw, ok := params["timeout_seconds"]; ok && raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			timeoutSec = n
		}
	}

	p := Params{
		Target:  target,
		Version: version,
		Timeout: time.Duration(timeoutSec) * time.Second,
	}

	switch version {
	case "v2c":
		community := strings.TrimSpace(params["community"])
		if community == "" {
			return Params{}, fmt.Errorf("snmp: missing param 'community' (required for v2c)")
		}
		p.Community = community
	case "v3":
		user := strings.TrimSpace(params["v3_user"])
		if user == "" {
			return Params{}, fmt.Errorf("snmp: missing param 'v3_user' (required for v3)")
		}
		p.V3User = user
		p.V3AuthProto = strDefault(params["v3_auth_proto"], "NoAuth")
		p.V3AuthPass = params["v3_auth_pass"]
		p.V3PrivProto = strDefault(params["v3_priv_proto"], "NoPriv")
		p.V3PrivPass = params["v3_priv_pass"]
		p.V3ContextName = params["v3_context"]
	default:
		return Params{}, fmt.Errorf("snmp: version invalida %q (esperado v2c ou v3)", version)
	}

	return p, nil
}

const defaultTimeoutSeconds = 5

func strDefault(v, def string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return def
	}
	return v
}
