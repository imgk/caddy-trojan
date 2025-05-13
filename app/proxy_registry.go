package app

import (
	"encoding/json"
	"fmt"
)

type ProxyParser func(args []string) (json.RawMessage, error)

var proxyParsers = make(map[string]ProxyParser)

func RegisterProxyParser(name string, parser ProxyParser) {
	if _, exists := proxyParsers[name]; exists {
		panic(fmt.Sprintf("proxy type already registered: %s", name))
	}
	proxyParsers[name] = parser
}

func GetProxyParser(name string) (ProxyParser, bool) {
	parser, ok := proxyParsers[name]
	return parser, ok
}
