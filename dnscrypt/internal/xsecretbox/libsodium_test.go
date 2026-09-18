package xsecretbox_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/holandyoung/dnsproxy/dnscrypt/internal/xsecretbox"
	"github.com/stretchr/testify/require"
)

func TestLibsodiumSecretboxVectors(t *testing.T) {
	// Generated independently using libsodium 1.0.18's
	// crypto_secretbox_xchacha20poly1305_easy, not this package's Seal.
	data, err := os.ReadFile("testdata/libsodium-1.0.18.json")
	require.NoError(t, err)
	var fixture struct {
		Version string `json:"version"`
		Key     string `json:"key"`
		Nonce   string `json:"nonce"`
		Vectors []struct {
			Ciphertext string `json:"ciphertext"`
			Length     int    `json:"length"`
		} `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(data, &fixture))
	key, err := hex.DecodeString(fixture.Key)
	require.NoError(t, err)
	nonce, err := hex.DecodeString(fixture.Nonce)
	require.NoError(t, err)
	for _, vector := range fixture.Vectors {
		t.Run(strconv.Itoa(vector.Length), func(t *testing.T) {
			message := make([]byte, vector.Length)
			for i := range message {
				message[i] = byte(i)
			}
			want, decodeErr := hex.DecodeString(vector.Ciphertext)
			require.NoError(t, decodeErr)
			require.Equal(t, want, xsecretbox.Seal(nil, nonce, message, key))
			plain, openErr := xsecretbox.Open(nil, nonce, want, key)
			require.NoError(t, openErr)
			require.True(t, bytes.Equal(message, plain))
			sealed := make([]byte, xsecretbox.TagSize+len(message))
			copy(sealed[xsecretbox.TagSize:], message)
			sealed = xsecretbox.Seal(sealed[:0], nonce, sealed[xsecretbox.TagSize:], key)
			require.Equal(t, want, sealed)
			plain, openErr = xsecretbox.Open(sealed[xsecretbox.TagSize:xsecretbox.TagSize], nonce, sealed, key)
			require.NoError(t, openErr)
			require.True(t, bytes.Equal(message, plain))
			for i := range want {
				corrupt := bytes.Clone(want)
				corrupt[i] ^= 1
				_, openErr = xsecretbox.Open(nil, nonce, corrupt, key)
				require.Error(t, openErr, "changed byte %d", i)
			}
		})
	}
}
