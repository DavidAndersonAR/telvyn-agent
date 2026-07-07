#!/usr/bin/env python3
"""
Conversor: profiles SNMP do Datadog (integrations-core) -> formato Telvyn/ISPWatch.

- Resolve `extends` recursivamente (guarda de ciclo + dedup de bloco de metric).
- Reescreve chaves MAIUSCULAS (OID/MIB) -> minusculas do nosso agente.
- IF-MIB: normaliza rótulo de interface (interface_name/interface_alias in-subtree),
  igual aos nossos profiles hand-curated (resolve o problema de tag cross-table).
- Politica de conflito: os prefixos em --own-oids pertencem aos nossos profiles
  hand-curated; sao removidos dos profiles do Datadog (e o profile do DD e' descartado
  se ficar sem sysObjectID) -> nossa curadoria vence o empate exato, deterministico.
- Descarta (com contagem) o que o agente Go nao modela: metric_type, mapping,
  index-tags, constant_value_one, tag por tabela cruzada nao-IF.
- Emite YAML no nosso estilo, com cabecalho de atribuicao (BSD-3 Datadog).

Uso:
  convert.py <dd_default_profiles_dir> <out_dir> [--only n1,n2] [--verbose]
"""
import os, sys, yaml
from collections import OrderedDict as OD

# Prefixos (base, sem .*) que pertencem aos nossos profiles hand-curated.
DEFAULT_OWN = [
    "1.3.6.1.4.1.9.1",            # cisco-ios (catch-all IOS)
    "1.3.6.1.4.1.9.12.3.1.3",     # cisco-nx-os
    "1.3.6.1.4.1.2636.1.1.1",     # juniper-junos
    "1.3.6.1.4.1.14988.1",        # mikrotik-routeros
    "1.3.6.1.4.1.8072.3.2.10",    # linux-net-snmp
    "1.3.6.1.4.1.5875",           # fiberhome-an5516
]

# Profiles do DD com sysObjectID amplo demais (catch-all): mantemos no catalogo
# mas como manual-only (auto_detect:false), pra nao roubar o auto-match. O nosso
# generic-snmpv2 continua sendo o fallback automatico (via codigo do agente).
FORCE_MANUAL = {"generic-device"}   # 1.3.6.1.4.* = arvore enterprises inteira

IFTABLE = "1.3.6.1.2.1.2.2"       # IF-MIB ifTable
IFXTABLE = "1.3.6.1.2.1.31.1.1"   # IF-MIB ifXTable

DROP = {"metric_type": 0, "mapping": 0, "index_tag": 0,
        "constant_value_one": 0, "cross_table_tag": 0, "empty_metric": 0}

def die(m): print(m, file=sys.stderr); sys.exit(1)

def load_raw(profiles_dir, name):
    fn = name if name.endswith(".yaml") else name + ".yaml"
    path = os.path.join(profiles_dir, fn)
    if not os.path.exists(path): return None
    with open(path) as f: return yaml.safe_load(f) or {}

def deep_merge(dst, src):
    for k, v in (src or {}).items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict): deep_merge(dst[k], v)
        else: dst[k] = v

def resolve(profiles_dir, name, seen):
    key = name if name.endswith(".yaml") else name + ".yaml"
    out = {"metrics": [], "metric_tags": [], "metadata": {}, "sysobjectid": [], "device": {}}
    if key in seen: return out
    seen.add(key)
    raw = load_raw(profiles_dir, name)
    if raw is None:
        print(f"  WARN: base ausente: {name}", file=sys.stderr); return out
    for base in (raw.get("extends") or []):
        sub = resolve(profiles_dir, base, seen)
        out["metrics"] += sub["metrics"]; out["metric_tags"] += sub["metric_tags"]
        deep_merge(out["metadata"], sub["metadata"]); out["device"].update(sub["device"])
        # NAO herdamos `sysobjectid` via extends — DE PROPOSITO. Isto espelha o
        # Datadog: `extends` compoe metrics/tags/metadata; o auto-match casa cada
        # profile pelo SEU proprio sysObjectID. Ex.: checkpoint-firewall so faz
        # `extends: checkpoint.yaml`; o device (2620.1.*) e coberto pelo profile
        # `checkpoint` (que tem o sysObjectID), e checkpoint-firewall fica manual-only.
        # Herdar aqui criaria COLISAO (dois profiles reclamando o mesmo prefixo).
    out["metrics"] += (raw.get("metrics") or [])
    out["metric_tags"] += (raw.get("metric_tags") or [])
    deep_merge(out["metadata"], raw.get("metadata") or {})
    out["device"].update(raw.get("device") or {})
    so = raw.get("sysobjectid")
    if so: out["sysobjectid"] += (so if isinstance(so, list) else [so])
    return out

def clean_oid(v):
    if v is None: return None
    s = str(v).strip().split("#", 1)[0].strip().strip("'").strip('"')
    return s or None

def base_oid(o):
    b = (clean_oid(o) or "").lstrip(".")
    if b.endswith(".*"): b = b[:-2]
    elif b.endswith("."): b = b[:-1]
    return b

def conv_symbol(s):
    if not isinstance(s, dict): return None
    if s.get("constant_value_one"): DROP["constant_value_one"] += 1; return None
    oid = clean_oid(s.get("OID") or s.get("oid")); name = s.get("name")
    if not oid or not name: return None
    return OD([("oid", oid), ("name", name)])

def conv_tag_in_table(tags, table_oid):
    """Tags dentro de um metric de tabela; so mantem symbol IN-SUBTREE do table_oid."""
    out = []
    for t in (tags or []):
        if not isinstance(t, dict): continue
        tag = t.get("tag")
        if "mapping" in t: DROP["mapping"] += 1
        if not tag:
            if "index" in t: DROP["index_tag"] += 1
            continue
        if isinstance(t.get("symbol"), dict):
            cs = conv_symbol(t["symbol"])
            if not cs: continue
            if table_oid and not (cs["oid"] == table_oid or cs["oid"].startswith(table_oid + ".")):
                DROP["cross_table_tag"] += 1  # ref a outra tabela: agente nao resolve
                continue
            out.append(OD([("tag", tag), ("symbol", cs)]))
        elif "value" in t:
            out.append(OD([("tag", tag), ("value", str(t["value"]))]))
        elif "index" in t:
            DROP["index_tag"] += 1
    return out

def if_tags(table_oid):
    """Rótulos canônicos de interface, in-subtree (espelha mikrotik-routeros)."""
    if table_oid == IFTABLE:
        return [OD([("tag", "interface_name"),
                    ("symbol", OD([("oid", IFTABLE + ".1.2"), ("name", "ifDescr")]))])]
    if table_oid == IFXTABLE:
        return [OD([("tag", "interface_name"),
                    ("symbol", OD([("oid", IFXTABLE + ".1.1"), ("name", "ifName")]))]),
                OD([("tag", "interface_alias"),
                    ("symbol", OD([("oid", IFXTABLE + ".1.18"), ("name", "ifAlias")]))])]
    return None

def conv_metric(m):
    if not isinstance(m, dict): return None
    if "metric_type" in m: DROP["metric_type"] += 1
    mib = m.get("MIB") or m.get("mib") or ""
    if isinstance(m.get("symbol"), dict):
        cs = conv_symbol(m["symbol"])
        if not cs: DROP["empty_metric"] += 1; return None
        return OD([("mib", mib), ("symbol", cs)])
    if isinstance(m.get("table"), dict):
        toid = clean_oid(m["table"].get("OID") or m["table"].get("oid"))
        tname = m["table"].get("name")
        syms = [cs for s in (m.get("symbols") or []) if (cs := conv_symbol(s))]
        if not toid or not syms: DROP["empty_metric"] += 1; return None
        out = OD([("mib", mib),
                  ("table", OD([("oid", toid), ("name", tname)])), ("symbols", syms)])
        canon = if_tags(toid)  # IF-MIB: rótulo canônico (ignora tags cross-table do DD)
        if canon is not None:
            out["metric_tags"] = canon
        else:
            mt = conv_tag_in_table(m.get("metric_tags"), toid)
            if mt: out["metric_tags"] = mt
        return out
    DROP["empty_metric"] += 1
    return None

def conv_root_tags(tags):
    out = []
    for t in (tags or []):
        if not isinstance(t, dict): continue
        tag = t.get("tag")
        if not tag: continue
        if "value" in t: out.append(OD([("tag", tag), ("value", str(t["value"]))])); continue
        oid = clean_oid(t.get("OID") or t.get("oid")); sym = t.get("symbol")
        name = sym if isinstance(sym, str) else (sym.get("name") if isinstance(sym, dict) else None)
        if oid and name:
            out.append(OD([("tag", tag), ("symbol", OD([("oid", oid), ("name", name)]))]))
    return out

def metric_sig(m):
    if "symbol" in m: return ("s", m["symbol"]["oid"])
    if "table" in m: return ("t", m["table"]["oid"], tuple(sorted(s["oid"] for s in m["symbols"])))
    return None

def vendor_of(name, device, metadata):
    if device.get("vendor"): return str(device["vendor"])
    try:
        v = metadata["device"]["fields"]["vendor"]["value"]
        if v: return str(v)
    except Exception: pass
    return name.split("-", 1)[0]

def convert(profiles_dir, name, own_oids):
    flat = resolve(profiles_dir, name, set())
    # sysObjectID (dedup + politica de conflito: nossa curadoria dona do prefixo exato)
    sysoids, seen_o, stripped = [], set(), 0
    for o in flat["sysobjectid"]:
        c = clean_oid(o)
        if not c or c in seen_o: continue
        seen_o.add(c)
        if base_oid(c) in own_oids: stripped += 1; continue
        sysoids.append(c)
    metrics, seen_sig = [], set()
    for m in flat["metrics"]:
        cm = conv_metric(m)
        if not cm: continue
        sig = metric_sig(cm)
        if sig in seen_sig: continue
        seen_sig.add(sig); metrics.append(cm)
    # Decisao de exclusao:
    #  - sysObjectID esvaziou porque ERA nosso (stripped>0)  -> conflito, descarta.
    #  - nunca teve sysObjectID e nem metrica                 -> vazio, descarta.
    #  - nunca teve sysObjectID mas TEM metrica               -> manual-only (mantem, sem auto-match).
    if not sysoids:
        if stripped > 0:
            return None, {"excluded": "conflito", "stripped": stripped}
        if not metrics:
            return None, {"excluded": "vazio", "stripped": stripped}
    rt, seen_rt = [], set()
    for t in conv_root_tags(flat["metric_tags"]):
        k = (t["tag"], t.get("value"), t.get("symbol", {}).get("oid") if t.get("symbol") else None)
        if k in seen_rt: continue
        seen_rt.add(k); rt.append(t)
    vendor = vendor_of(name, flat["device"], flat["metadata"])
    if not any(t["tag"] == "vendor" for t in rt):
        rt.append(OD([("tag", "vendor"), ("value", vendor)]))
    rt.append(OD([("tag", "profile"), ("value", name)]))
    prof = OD()
    if sysoids: prof["sysobjectid"] = sysoids
    if name in FORCE_MANUAL: prof["auto_detect"] = False
    if metrics: prof["metrics"] = metrics
    if rt: prof["metric_tags"] = rt
    manual = (name in FORCE_MANUAL) or not sysoids
    cat = ("manual" if manual else "auto") if metrics else "so_id"
    return prof, {"metrics": len(metrics), "sysoids": len(sysoids),
                  "tags": len(rt), "stripped": stripped, "cat": cat}

class Dumper(yaml.SafeDumper): pass
Dumper.add_representer(OD, lambda d, data: d.represent_dict(data.items()))

HEADER = ("# Telvyn SNMP profile — {name}\n"
          "# Convertido da biblioteca oficial do Datadog (integrations-core, BSD-3-Clause).\n"
          "# Fonte: snmp/datadog_checks/snmp/data/default_profiles/{name}.yaml\n"
          "# `extends` resolvido em build; recursos nao suportados pelo agente descartados.\n"
          "# NAO editar a mao — regenerar via tools/convert-datadog-profiles/convert.py.\n\n")

def emit(prof, name):
    body = yaml.dump(prof, Dumper=Dumper, default_flow_style=False,
                     sort_keys=False, allow_unicode=True, width=100)
    return HEADER.format(name=name) + body

def main():
    if len(sys.argv) < 3: die(__doc__)
    pdir, outdir = sys.argv[1], sys.argv[2]
    only = None; verbose = False; own = set(DEFAULT_OWN)
    args = sys.argv[3:]
    for i, a in enumerate(args):
        if a == "--only": only = set(args[i + 1].split(","))
        if a == "--own-oids": own = set(args[i + 1].split(","))
        if a == "--verbose": verbose = True
    os.makedirs(outdir, exist_ok=True)
    devices = sorted(f[:-5] for f in os.listdir(pdir)
                     if f.endswith(".yaml") and not f.startswith("_"))
    if only: devices = [d for d in devices if d in only]
    cats = {"auto": [], "manual": [], "so_id": []}
    excl = {"conflito": [], "vazio": []}
    for d in devices:
        prof, s = convert(pdir, d, own)
        if prof is None:
            excl[s["excluded"]].append(d); continue
        cats[s["cat"]].append(d)
        open(os.path.join(outdir, d + ".yaml"), "w").write(emit(prof, d))
        if verbose:
            print(f"  {d:34s} [{s['cat']:6s}] metrics={s['metrics']:3d} sysoids={s['sysoids']:4d} strip={s['stripped']}")
    gerados = len(cats["auto"]) + len(cats["manual"]) + len(cats["so_id"])
    print(f"\n== RESULTADO ==")
    print(f"devices no DD: {len(devices)}  gerados: {gerados}")
    print(f"  auto-match (id+metrica): {len(cats['auto'])}")
    print(f"  manual-only (metrica s/ id): {len(cats['manual'])}  -> {', '.join(cats['manual'])}")
    print(f"  so-identificacao (id s/ metrica): {len(cats['so_id'])}  -> {', '.join(cats['so_id'])}")
    print(f"  excluidos(conflito c/ nossa curadoria): {len(excl['conflito'])}  -> {', '.join(excl['conflito'])}")
    print(f"  excluidos(vazio, fiel ao DD): {len(excl['vazio'])}  -> {', '.join(excl['vazio'])}")
    print(f"features descartadas (esperado): {dict(DROP)}")

if __name__ == "__main__":
    main()
