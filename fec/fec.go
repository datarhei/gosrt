package fec

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	MinCols = 2    // MinCols is the smallest supported row size.
	MaxCols = 1024 // MaxCols is the largest supported row size.
)

// Config represents the parsed FEC configuration.
type Config struct {
	Cols   int
	Rows   int
	Layout string // "even" or "staircase". Has no effect with row-only FEC.
	ARQ    string // ARQ is "always", "onreq" or "never". It is accepted for compatibility with libsrt, which defaults to "onreq".
}

var knownKeys = map[string]bool{
	"cols":   true,
	"rows":   true,
	"layout": true,
	"arq":    true,
}

// parseFilter splits a filter string into its type and key/value pairs. It rejects malformed parts, unknown keys and duplicate keys.
func parseFilter(filterStr string) (string, map[string]string, error) {
	parts := strings.Split(filterStr, ",")

	filterType := strings.ToLower(strings.TrimSpace(parts[0]))
	if filterType != "fec" {
		return "", nil, fmt.Errorf("unsupported packet filter type %q", parts[0])
	}

	kv := map[string]string{}

	for _, part := range parts[1:] {
		key, val, ok := strings.Cut(part, ":")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)

		if !ok || len(key) == 0 || len(val) == 0 {
			return "", nil, fmt.Errorf("invalid packet filter parameter %q, expecting key:value", part)
		}

		if !knownKeys[key] {
			return "", nil, fmt.Errorf("unknown packet filter parameter %q", key)
		}

		if _, ok := kv[key]; ok {
			return "", nil, fmt.Errorf("duplicate packet filter parameter %q", key)
		}

		kv[key] = val
	}

	return filterType, kv, nil
}

// ParseConfig parses a packet filter string into an FEC config.
//
// Example: "fec,cols:10" or "fec,cols:10,rows:1,layout:even,arq:always"
func ParseConfig(filterStr string) (Config, error) {
	cfg := Config{
		Cols:   0,
		Rows:   1,
		Layout: "even",
		ARQ:    "always",
	}

	_, kv, err := parseFilter(filterStr)
	if err != nil {
		return cfg, err
	}

	val, ok := kv["cols"]
	if !ok {
		return cfg, fmt.Errorf("cols must be specified")
	}

	cols, err := strconv.Atoi(val)
	if err != nil || cols < MinCols || cols > MaxCols {
		return cfg, fmt.Errorf("invalid cols %q, must be between %d and %d", val, MinCols, MaxCols)
	}
	cfg.Cols = cols

	if val, ok := kv["rows"]; ok {
		rows, err := strconv.Atoi(val)
		if err != nil || rows != 1 {
			return cfg, fmt.Errorf("invalid rows %q, only row FEC (rows:1) is supported", val)
		}
		cfg.Rows = rows
	}

	if val, ok := kv["layout"]; ok {
		if val != "even" && val != "staircase" {
			return cfg, fmt.Errorf("invalid layout %q", val)
		}
		cfg.Layout = val
	}

	if val, ok := kv["arq"]; ok {
		if val != "always" && val != "onreq" && val != "never" {
			return cfg, fmt.Errorf("invalid arq %q", val)
		}
		cfg.ARQ = val
	}

	return cfg, nil
}

// Negotiate merges the local and the peer's packet filter configuration, as the listener does during the HSv5 handshake.
//
// Parameters set on only one side are taken over.
//
// If both sides set the same parameter to different values, the configurations are incompatible.
// The merged configuration must be supported by this package.
//
// If the peer has no filter, the local configuration is returned unchanged.
//
// If only the peer has a filter, no filter is used (the empty string is returned).
func Negotiate(local, peer string) (string, error) {
	if len(peer) == 0 || len(local) == 0 {
		if len(local) != 0 {
			if _, err := ParseConfig(local); err != nil {
				return "", err
			}
		}

		return local, nil
	}

	localType, localKV, err := parseFilter(local)
	if err != nil {
		return "", fmt.Errorf("local: %w", err)
	}

	peerType, peerKV, err := parseFilter(peer)
	if err != nil {
		return "", fmt.Errorf("peer: %w", err)
	}

	if localType != peerType {
		return "", fmt.Errorf("packet filter type mismatch (local %q, peer %q)", localType, peerType)
	}

	merged := []string{localType}

	for _, key := range []string{"cols", "rows", "layout", "arq"} {
		lval, lok := localKV[key]
		pval, pok := peerKV[key]

		if lok && pok && lval != pval {
			return "", fmt.Errorf("packet filter parameter %q mismatch (local %q, peer %q)", key, lval, pval)
		}

		if lok {
			merged = append(merged, key+":"+lval)
		} else if pok {
			merged = append(merged, key+":"+pval)
		}
	}

	result := strings.Join(merged, ",")

	if _, err := ParseConfig(result); err != nil {
		return "", err
	}

	return result, nil
}
