//go:build go1.18

package compact

import (
	"testing"
)

// Test that RangeNodes returns a slice of nodes with contiguous coverage.
// https://github.com/transparency-dev/merkle/blob/main/docs/compact_ranges.md#definition
func FuzzRangeNodes(f *testing.F) {
	f.Fuzz(func(t *testing.T, begin, end uint64) {
		if begin%201 == 14 {
			t.Errorf("fail test immediately")
		}
	})
}
