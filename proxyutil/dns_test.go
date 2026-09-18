package proxyutil

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLengthPrefixBounds(t *testing.T) {
	for _, size := range []int{0, 12, 65535} {
		prefix, err := LengthPrefix(size)
		require.NoError(t, err)
		require.Equal(t, size, int(binary.BigEndian.Uint16(prefix[:])))
	}
	for _, size := range []int{-1, 65536} {
		_, err := LengthPrefix(size)
		require.Error(t, err)
	}
}
