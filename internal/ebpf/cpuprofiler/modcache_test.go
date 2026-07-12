package cpuprofiler

import "testing"

func TestModLRU_MissThenNegativeAndPositive(t *testing.T) {
	c := newModLRU(3)
	if _, ok := c.get("a"); ok {
		t.Fatal("esperava miss no cache vazio")
	}
	// cache negativo: nil é um valor cacheado VÁLIDO (found=true, val=nil)
	c.put("a", nil)
	if v, ok := c.get("a"); !ok || v != nil {
		t.Fatalf("cache negativo: got (%v,%v), want (nil,true)", v, ok)
	}
	m := &modSyms{}
	c.put("b", m)
	if v, ok := c.get("b"); !ok || v != m {
		t.Fatalf("positivo: got (%v,%v), want (%p,true)", v, ok, m)
	}
	if c.len() != 2 {
		t.Fatalf("len=%d want 2", c.len())
	}
}

func TestModLRU_EvictsLeastRecentlyUsed(t *testing.T) {
	c := newModLRU(2)
	c.put("a", nil)
	c.put("b", nil)
	c.put("c", nil) // estoura → despeja "a" (menos-recém-usado)
	if _, ok := c.get("a"); ok {
		t.Fatal("a deveria ter sido despejado")
	}
	if _, ok := c.get("b"); !ok {
		t.Fatal("b deveria estar presente")
	}
	if _, ok := c.get("c"); !ok {
		t.Fatal("c deveria estar presente")
	}
	if c.len() != 2 {
		t.Fatalf("len=%d want 2", c.len())
	}
}

func TestModLRU_GetPromotes(t *testing.T) {
	c := newModLRU(2)
	c.put("a", nil)
	c.put("b", nil)
	if _, ok := c.get("a"); !ok { // toca "a" → vira MRU
		t.Fatal("a presente")
	}
	c.put("c", nil) // agora despeja "b" (LRU), não "a"
	if _, ok := c.get("a"); !ok {
		t.Fatal("a deveria sobreviver (foi promovido pelo get)")
	}
	if _, ok := c.get("b"); ok {
		t.Fatal("b deveria ter sido despejado")
	}
}

func TestModLRU_UpdatePromotesAndDoesNotGrow(t *testing.T) {
	c := newModLRU(2)
	m1, m2 := &modSyms{}, &modSyms{}
	c.put("a", m1)
	c.put("b", nil)
	c.put("a", m2) // atualiza "a" (não cria entrada nova) e promove a MRU
	if c.len() != 2 {
		t.Fatalf("len=%d want 2 (update não deve crescer)", c.len())
	}
	if v, _ := c.get("a"); v != m2 {
		t.Fatalf("update: got %p want %p", v, m2)
	}
	c.put("c", nil) // despeja "b" (LRU), não "a"
	if _, ok := c.get("b"); ok {
		t.Fatal("b deveria ter sido despejado")
	}
	if _, ok := c.get("a"); !ok {
		t.Fatal("a deveria sobreviver (update promoveu)")
	}
}

func TestModLRU_CapacityFloor(t *testing.T) {
	c := newModLRU(0) // piso = 1
	c.put("a", nil)
	c.put("b", nil) // despeja "a"
	if c.len() != 1 {
		t.Fatalf("len=%d want 1", c.len())
	}
	if _, ok := c.get("b"); !ok {
		t.Fatal("b deveria estar presente")
	}
}
