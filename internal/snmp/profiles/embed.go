// Package profiles bundles all SNMP vendor profile YAMLs into the binary
// via embed.FS. The package exists in its own directory so //go:embed
// pode usar path relativo aos YAMLs sem cair no pitfall do ../ proibido
// (RESEARCH.md §Common Pitfalls — embed.FS path resolution).
//
// Adicionar um vendor novo = colocar `<vendor>.yaml` aqui e recompilar.
// Nenhuma mudanca em codigo Go e necessaria; o loader em internal/snmp
// itera FS via fs.ReadDir.
package profiles

import "embed"

// FS expoe os YAMLs bundled. Consumido por internal/snmp/profile.go via
// fs.ReadFile / fs.ReadDir.
//
//go:embed *.yaml
var FS embed.FS
