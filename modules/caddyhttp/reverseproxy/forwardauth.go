package reverseproxy

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddyfile.RegisterDirective("forward_auth", parseForwardAuth)
}

func parseForwardAuth(h *caddyfile.Helper) ([]caddyfile.ConfigValue, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	var to []string
	if !h.AllArgs(&to) {
		return nil, h.ArgErr()
	}

	var copyHeaders []string
	var uri string
	var headerUp []string
	var headerDown []string

	for h.NextBlock(0) {
		switch h.Val() {
		case "copy_headers":
			copyHeaders = h.RemainingArgs()
			if len(copyHeaders) == 0 {
				return nil, h.ArgErr()
			}
		case "uri":
			if !h.AllArgs(&uri) {
				return nil, h.ArgErr()
			}
		case "header_up":
			headerUp = append(headerUp, h.RemainingArgs()...)
		case "header_down":
			headerDown = append(headerDown, h.RemainingArgs()...)
		default:
			return nil, h.Errf("unrecognized subdirective '%s'", h.Val())
		}
	}

	var tokens []caddyfile.Token

	// helper function to add a token
	add := func(text string) {
		tokens = append(tokens, caddyfile.Token{Text: text})
	}

	add("reverse_proxy")
	for _, t := range to {
		add(t)
	}
	add("{")

	add("method")
	add("GET")

	if uri != "" {
		add("rewrite")
		add(uri)
	}

	// copy original request headers
	add("header_up")
	add("Host")
	add("{http.request.host}")

	add("header_up")
	add("X-Forwarded-Method")
	add("{http.request.method}")

	add("header_up")
	add("X-Forwarded-Uri")
	add("{http.request.uri}")

	for _, h := range headerUp {
		add("header_up")
		add(h)
	}

	for _, h := range headerDown {
		add("header_down")
		add(h)
	}

	if len(copyHeaders) > 0 {
		add("handle_response")
		add("{")
		add("@ok")
		add("status")
		add("2xx")
		add("handle")
		add("@ok")
		add("{")
		for _, h := range copyHeaders {
			add("request_header")
			add("-" + h)
		}
		for _, h := range copyHeaders {
			add("request_header")
			add(h)
			add(fmt.Sprintf("{rp.header.%s}", h))
		}
		add("}")
		add("}")
	}

	add("}")

	return []caddyfile.ConfigValue{
		{
			Directive: "reverse_proxy",
			Value:     tokens,
		},
	}, nil
}