package domaintree

import "strings"

func NewNode() Node {
	return Node{Next: map[string]*Node{}}
}

type Node struct {
	Next map[string]*Node
}

func (nd *Node) Put(domain string) {
	const sep = "."

	nd.store(strings.Split(strings.TrimSuffix(domain, sep), sep))
}

func (nd *Node) store(ks []string) {
	l := len(ks)
	switch l {
	case 0:
		return
	case 1:
		k := ks[l-1]

		if k == "**" {
			nd.Next[k] = (*Node)(nil)
			return
		}

		_, ok := nd.Next[k]
		if ok {
			return
		}

		nd.Next[k] = &Node{
			Next: map[string]*Node{},
		}
	default:
		k := ks[l-1]

		b, ok := nd.Next[k]
		if !ok {
			b = &Node{
				Next: map[string]*Node{},
			}
			nd.Next[k] = b
		}

		b.store(ks[:l-1])
	}
}

func (nd *Node) Get(domain string) bool {
	const sep = "."

	return nd.load(strings.Split(strings.TrimSuffix(domain, sep), sep))
}

func (nd *Node) load(ks []string) bool {
	l := len(ks)
	switch l {
	case 0:
		return false
	case 1:
		_, ok := nd.Next[ks[l-1]]
		if ok {
			return true
		}

		_, ok = nd.Next["*"]
		if ok {
			return true
		}

		_, ok = nd.Next["**"]
		if ok {
			return true
		}

		return false
	default:
		b, ok := nd.Next[ks[l-1]]
		if ok {
			return b.load(ks[:l-1])
		}

		b, ok = nd.Next["*"]
		if ok {
			return b.load(ks[:l-1])
		}

		_, ok = nd.Next["**"]
		if ok {
			return true
		}

		return false
	}
}
