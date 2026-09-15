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

// encryptedResponse is used for encrypting/decrypting server responses.
//
// NOTE: Server responses are using the following schema:
//
//	<dnscrypt-response> ::= <resolver-magic> <nonce> <encrypted-response>
//	<encrypted-response> ::= AE(<shared-key>, <nonce>, <resolver-response> <resolver-response-pad>)
type encryptedResponse struct {
	// esVersion is the encryption to use.
	esVersion CryptoConstruction

	// nonce is used to decrypt a response.
	nonce nonce
}

// encrypt encrypts the server response.  r.esVersion and r.nonce must be set.
func (r *encryptedResponse) encrypt(
	packet []byte,
	sharedKey [SharedKeySize]byte,
) (response []byte, err error) {
	_, _ = rand.Read(r.nonce[12:16])
	binary.BigEndian.PutUint64(r.nonce[16:nonceSize], uint64(time.Now().UnixNano()))

	response = append(response, resolverMagic[:]...)
	response = append(response, r.nonce[:]...)

	padded := pad(packet)

	serverNonce := r.nonce
	switch r.esVersion {
	case XChacha20Poly1305:
		response = xsecretbox.Seal(response, serverNonce[:], padded, sharedKey[:])
	case XSalsa20Poly1305:
		var xsalsaNonce nonce
		copy(xsalsaNonce[:], serverNonce[:])
		response = secretbox.Seal(response, padded, &xsalsaNonce, &sharedKey)
	default:
		return nil, ErrESVersion
	}

	return response, nil
}

// decrypt decrypts the server response.  r.esVersion must be set.
func (r *encryptedResponse) decrypt(
	response []byte,
	sharedKey [SharedKeySize]byte,
	clientNonce nonce,
) (packet []byte, err error) {
	headerLength := len(resolverMagic) + nonceSize
	if len(response) < headerLength+xsecretbox.TagSize+minDNSPacketSize {
		return nil, ErrInvalidResponse
	}

	magic := [resolverMagicSize]byte{}
	copy(magic[:], response[:resolverMagicSize])
	if !bytes.Equal(magic[:], resolverMagic[:]) {
		return nil, ErrInvalidResolverMagic
	}

	copy(r.nonce[:], response[resolverMagicSize:nonceSize+resolverMagicSize])

	// NOTE: Ensure that the client nonce received from the server matches the
	// actual client nonce.  See AGDNS-4183.
	if !bytes.Equal(r.nonce[:nonceSize/2], clientNonce[:nonceSize/2]) {
		return nil, ErrUnexpectedNonce
	}

	encryptedResponse := response[nonceSize+resolverMagicSize:]
	switch r.esVersion {
	case XChacha20Poly1305:
		packet, err = xsecretbox.Open(nil, r.nonce[:], encryptedResponse, sharedKey[:])
		if err != nil {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.esVersion, err)
		}
	case XSalsa20Poly1305:
		var xsalsaServerNonce nonce
		copy(xsalsaServerNonce[:], r.nonce[:])
		var ok bool
		packet, ok = secretbox.Open(nil, encryptedResponse, &xsalsaServerNonce, &sharedKey)
		if !ok {
			return nil, fmt.Errorf("decrypting response: %s: %w", r.esVersion, ErrInvalidResponse)
		}
	default:
		return nil, ErrESVersion
	}

	packet, err = unpad(packet)
	if err != nil {
		return nil, fmt.Errorf("removing packet padding: %w", err)
	}

	return packet, nil
}
