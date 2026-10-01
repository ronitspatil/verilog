package keys

import "container/list"

// lru is a fixed-capacity map that evicts its least recently used entry. It
// is not safe for concurrent use.
type lru[K comparable, V any] struct {
	cap   int
	order *list.List // front: most recently used; values are *lruItem
	items map[K]*list.Element
}

type lruItem[K comparable, V any] struct {
	key K
	val V
}

func newLRU[K comparable, V any](capacity int) *lru[K, V] {
	return &lru[K, V]{cap: capacity, order: list.New(), items: make(map[K]*list.Element)}
}

func (l *lru[K, V]) get(k K) (V, bool) {
	if el, ok := l.items[k]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*lruItem[K, V]).val, true
	}
	var zero V
	return zero, false
}

func (l *lru[K, V]) put(k K, v V) {
	if el, ok := l.items[k]; ok {
		el.Value.(*lruItem[K, V]).val = v
		l.order.MoveToFront(el)
		return
	}
	l.items[k] = l.order.PushFront(&lruItem[K, V]{key: k, val: v})
	for l.order.Len() > l.cap {
		old := l.order.Back()
		l.order.Remove(old)
		delete(l.items, old.Value.(*lruItem[K, V]).key)
	}
}

func (l *lru[K, V]) len() int { return l.order.Len() }
