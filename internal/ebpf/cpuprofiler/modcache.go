package cpuprofiler

import "container/list"

// modLRU é um cache LRU limitado de índices de símbolos por módulo, chaveado por
// dev:inode. Guarda também resultados NEGATIVOS (val == nil): um módulo parseado
// e sem símbolo é um desfecho válido e cacheável (evita reabrir o ELF toda janela).
//
// Single-goroutine por design — só a goroutine de flush do profiler toca o cache
// (foldLine → symbolizer.user → modFor). NÃO tem trava; adicionar concorrência
// exigiria mutex (container/list não é thread-safe).
//
// Substitui o backstop antigo que ZERAVA o mapa inteiro ao passar de 4096: num nó
// denso (muitos binários distintos) isso reabria TODOS os binários de uma vez na
// janela seguinte — tempestade de CPU + o parse transitório de vários .gopclntab
// gigantes ao mesmo tempo (risco de OOM). A LRU descarta só o menos-recém-usado,
// um de cada vez, mantendo os quentes.
type modLRU struct {
	cap   int
	ll    *list.List               // frente = mais-recém-usado, fundo = menos
	items map[string]*list.Element // dev:inode → elemento com *modEntry
}

type modEntry struct {
	key string
	val *modSyms // pode ser nil (cache negativo)
}

func newModLRU(capacity int) *modLRU {
	if capacity < 1 {
		capacity = 1
	}
	return &modLRU{
		cap:   capacity,
		ll:    list.New(),
		items: make(map[string]*list.Element, capacity),
	}
}

// get devolve o valor cacheado e se a chave existia. Chave presente com val nil é
// um acerto de cache NEGATIVO válido (found=true, val=nil) — não reparseia.
func (c *modLRU) get(key string) (val *modSyms, found bool) {
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*modEntry).val, true
	}
	return nil, false
}

// put insere/atualiza key→val marcando como mais-recém-usado e evita o cache
// crescer sem limite: enquanto passar da capacidade, remove o menos-recém-usado.
func (c *modLRU) put(key string, val *modSyms) {
	if el, ok := c.items[key]; ok {
		el.Value.(*modEntry).val = val
		c.ll.MoveToFront(el)
		return
	}
	c.items[key] = c.ll.PushFront(&modEntry{key: key, val: val})
	for c.ll.Len() > c.cap {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		delete(c.items, back.Value.(*modEntry).key)
	}
}

// len devolve o número de entradas cacheadas (usado em teste).
func (c *modLRU) len() int { return c.ll.Len() }
