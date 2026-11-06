package live

import (
	"fmt"
	"testing"

	"github.com/datarhei/gosrt/circular"
	"github.com/stretchr/testify/require"
)

func TestDropFreshLossIntervals(t *testing.T) {
	type span struct {
		from, to uint32
		ttl      int
	}
	tests := []struct {
		name        string
		input       []span
		first, last uint32
		want        []span
	}{
		{"empty", nil, 3, 5, nil},
		{"before", []span{{10, 15, 3}}, 3, 9, []span{{10, 15, 3}}},
		{"after", []span{{10, 15, 3}}, 16, 18, []span{{10, 15, 3}}},
		{"exact", []span{{10, 15, 3}}, 10, 15, nil},
		{"cover", []span{{10, 15, 3}}, 9, 16, nil},
		{"prefix", []span{{10, 15, 0}}, 9, 12, []span{{13, 15, 0}}},
		{"suffix", []span{{10, 15, -1}}, 13, 18, []span{{10, 12, -1}}},
		{"middle", []span{{10, 15, 3}, {20, 25, 7}}, 12, 13, []span{{10, 11, 3}, {14, 15, 3}, {20, 25, 7}}},
		{"single-first", []span{{10, 15, 3}}, 10, 10, []span{{11, 15, 3}}},
		{"single-last", []span{{10, 15, 3}}, 15, 15, []span{{10, 14, 3}}},
		{"across", []span{{10, 15, 0}, {20, 25, 3}, {30, 35, 7}, {40, 45, 8}}, 12, 32, []span{{10, 11, 0}, {33, 35, 7}, {40, 45, 8}}},
		{"between", []span{{10, 15, 0}, {20, 25, 3}}, 16, 19, []span{{10, 15, 0}, {20, 25, 3}}},
	}
	for _, base := range []uint32{100, 0x7ffffff2} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%d/%s", base, tt.name), func(t *testing.T) {
				seq := func(n uint32) circular.Number { return dropSeq(base).Add(n) }
				r := dropReceiver(base)
				for _, s := range tt.input {
					r.freshLoss = append(r.freshLoss, freshLoss{seq(s.from), seq(s.to), s.ttl})
				}
				r.dropFreshLoss(seq(tt.first), seq(tt.last))
				want := make([]freshLoss, 0, len(tt.want))
				for _, s := range tt.want {
					want = append(want, freshLoss{seq(s.from), seq(s.to), s.ttl})
				}
				require.Equal(t, want, append([]freshLoss{}, r.freshLoss...))
			})
		}
	}
}
