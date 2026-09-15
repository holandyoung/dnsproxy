package dnscrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/holandyoung/dnsproxy/dnscrypt/internal/xsecretbox"
	"golang.org/x/crypto/nacl/secretbox"
)

// encryptedQuery is a structure for encrypting and decrypting client queries.
//
// NOTE: Client Queries are using the following schema:
//
//	<dnscrypt-query> ::= <client-magic> <client-pk> <client-nonce> <encrypted-query>
//	<encrypted-query> ::= AE(<shared-key> <client-nonce> <client-nonce-pad>, <client-query> <client-query-pad>)
type encryptedQuery struct {
	// esVersion contains used encryption.
	esVersion CryptoConstruction

	// clientMagic is a 8 byte identifier for the resolver certificate chosen by
	// the client.
	clientMagic [clientMagicSize]byte

	// clientPk is the client's public key.
	clientPk [KeySize]byte

	// nonce is used to encrypt a query.  With a 24 bytes nonce, a question sent
	// by a DNSCrypt client must be encrypted using the shared secret, and a
	// nonce constructed as follows: 12 bytes chosen by the client followed by
	// 12 zero bytes.  The client's half of the nonce can include a timestamp in
	// addition to a counter or to random bytes, so that when a response is
	// received, the client can use this timestamp to immediately discard
	// responses to queries that have been sent too long ago, or dated in the
	// future.
	nonce nonce
}

// encrypt encrypts the specified DNS query, returns encrypted data ready to be
// sent.  q.esVersion, q.clientMagic and q.clientPk must be set.
func (q *encryptedQuery) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (query []byte, clientNonce nonce, err error) {
	binary.BigEndian.PutUint64(q.nonce[:8], uint64(time.Now().UnixNano()))
	_, _ = rand.Read(q.nonce[8:12])

	query = append(query, q.clientMagic[:]...)
	query = append(query, q.clientPk[:]...)
	query = append(query, q.nonce[:nonceSize/2]...)

	padded := pad(packet)

	clientNonce = q.nonce
	switch q.esVersion {
	case XChacha20Poly1305:
		query = xsecretbox.Seal(query, clientNonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce nonce
		copy(xsalsaNonce[:], clientNonce[:])
		query = secretbox.Seal(query, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, nonce{}, ErrESVersion
	}

	return query, clientNonce, nil
}

// decrypt decrypts the client query, returns decrypted DNS packet.
// q.clientMagic and q.esVersion must be set.
func (q *encryptedQuery) decrypt(
	query []byte,
	serverSecretKey [KeySize]byte,
) (packet []byte, err error) {
	headerLength := clientMagicSize + KeySize + nonceSize/2
	if len(query) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidQuery
	}

	clientMagic := [clientMagicSize]byte{}
	copy(clientMagic[:], query[:clientMagicSize])
	if !bytes.Equal(clientMagic[:], q.clientMagic[:]) {
		return nil, ErrInvalidClientMagic
	}

	idx := clientMagicSize
	copy(q.clientPk[:KeySize], query[idx:idx+KeySize])

	sharedKey, err := computeSharedKey(q.esVersion, &serverSecretKey, &q.clientPk)
	if err != nil {
		return nil, fmt.Errorf("computing shared key: %w", err)
	}

	idx = idx + KeySize
	copy(q.nonce[:nonceSize/2], query[idx:idx+nonceSize/2])

	idx = idx + nonceSize/2
	encryptedQuery := query[idx:]

	packet, err = q.decryptES(encryptedQuery, sharedKey)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("remove packet padding: %w", err)
	}

	return packet, nil
}

// decryptES decrypts the query using the configured encryption method and the
// given shared key.
func (q *encryptedQuery) decryptES(
	query []byte,
	sharedKey [xsecretbox.KeySize]byte,
) (packet []byte, err error) {
	switch q.esVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, q.nonce[:], query, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.esVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce nonce
		copy(xsalsaServerNonce[:], q.nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, query, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting query: %s: %w", q.esVersion, ErrInvalidQuery)
		}
	default:
		return nil, ErrESVersion
	}

	return packet, nil
}
