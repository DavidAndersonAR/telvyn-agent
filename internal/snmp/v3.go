package snmp

// Helpers de mapeamento dos protocolos USM da version v3 — AuthProto,
// PrivProto e MsgFlags traduzem nomes textuais (vindos do CheckConfig
// ou dos args do tool) para as constantes do gosnmp.

import (
	"fmt"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// AuthProto mapeia o nome textual do protocolo de autenticacao USM (SNMPv3)
// para a constante gosnmp correspondente. O matching e case-insensitive
// para evitar atrito no schema do CheckConfig.params.
//
// Protocolos suportados: NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512.
// MD5 e SHA estao mantidos por compatibilidade com equipamentos legados —
// novos perfis devem preferir SHA256 ou acima.
func AuthProto(s string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NOAUTH":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	}
	return 0, fmt.Errorf("snmp: protocolo de autenticacao desconhecido %q (validos: NoAuth, MD5, SHA, SHA224, SHA256, SHA384, SHA512)", s)
}

// PrivProto mapeia o nome textual do protocolo de privacidade USM (SNMPv3)
// para a constante gosnmp.
//
// AES192/AES256 e AES192C/AES256C sao DUAS variantes incompativeis do AES
// estendido para SNMPv3. A nomenclatura nas duas pontas (gosnmp e RFC) e
// confusa — o que importa e: equipamentos Cisco IOS XE recentes falham se
// o agente usar a variante errada. Por isso expomos ambas no schema e
// deixamos o perfil escolher.
//
// Referencia: 03-RESEARCH.md Pitfall 1.
func PrivProto(s string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NOPRIV":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	}
	return 0, fmt.Errorf("snmp: protocolo de privacidade desconhecido %q (validos: NoPriv, DES, AES, AES192, AES192C, AES256, AES256C)", s)
}

// MsgFlags deriva o flag de mensagem USM a partir das escolhas de auth/priv.
// Rejeita a combinacao NoAuth+Priv porque a USM (RFC 3414, secao 1.4) so
// permite NoAuthNoPriv, AuthNoPriv ou AuthPriv — privacidade sem autenticacao
// nao oferece prova de origem, entao a spec proibe.
func MsgFlags(auth gosnmp.SnmpV3AuthProtocol, priv gosnmp.SnmpV3PrivProtocol) (gosnmp.SnmpV3MsgFlags, error) {
	if auth == gosnmp.NoAuth && priv != gosnmp.NoPriv {
		return 0, fmt.Errorf("snmp: combinacao NoAuth+Priv nao permitida pela RFC 3414")
	}
	if auth == gosnmp.NoAuth {
		return gosnmp.NoAuthNoPriv, nil
	}
	if priv == gosnmp.NoPriv {
		return gosnmp.AuthNoPriv, nil
	}
	return gosnmp.AuthPriv, nil
}
