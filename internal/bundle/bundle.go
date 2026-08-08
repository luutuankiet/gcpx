// Package bundle seals a credential for transport between hosts.
//
// Encryption is not optional. A credential moved between machines is a live
// OAuth refresh token, and the transport is frequently an agent's transcript
// or a paste buffer. Ciphertext keeps the secret out of both.
//
// Envelope: "gcpx-bundle-v1:" + base64(salt[16] || nonce[12] || AES-256-GCM).
// Key derivation is PBKDF2-HMAC-SHA256. Zero external dependencies.
package bundle

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const (
	prefix     = "gcpx-bundle-v1:"
	saltLen    = 16
	keyLen     = 32
	iterations = 600000
)

// Seal encrypts plaintext under a passphrase.
func Seal(plaintext []byte, passphrase string) (string, error) {
	if passphrase == "" {
		return "", errors.New("empty passphrase")
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	env := append(append(append([]byte{}, salt...), nonce...), ct...)
	return prefix + base64.StdEncoding.EncodeToString(env), nil
}

// Open decrypts a sealed bundle.
func Open(envelope, passphrase string) ([]byte, error) {
	envelope = strings.TrimSpace(envelope)
	if !strings.HasPrefix(envelope, prefix) {
		return nil, errors.New("not a gcpx bundle (missing gcpx-bundle-v1 header)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(envelope, prefix))
	if err != nil {
		return nil, fmt.Errorf("corrupt bundle: %w", err)
	}
	if len(raw) < saltLen+12+16 {
		return nil, errors.New("corrupt bundle: too short")
	}
	salt := raw[:saltLen]
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	nonce := raw[saltLen : saltLen+ns]
	pt, err := gcm.Open(nil, nonce, raw[saltLen+ns:], nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong passphrase or corrupt bundle")
	}
	return pt, nil
}
