package encrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

//
// --- AES-256-CBC with Random IV ---
//

func EncryptDataRandomIV(plainText, encryptionKey string) (string, error) {
	key := []byte(encryptionKey)
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padding := aes.BlockSize - len(plainText)%aes.BlockSize
	padText := append([]byte(plainText), bytes.Repeat([]byte{byte(padding)}, padding)...)

	cipherText := make([]byte, len(padText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, padText)

	// Return iv:encryptedHex
	return hex.EncodeToString(iv) + ":" + hex.EncodeToString(cipherText), nil
}

func DecryptDataRandomIV(encryptedData, encryptionKey string) (string, error) {
	parts := strings.Split(encryptedData, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted data format")
	}

	iv, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	cipherText, err := hex.DecodeString(parts[1])
	if err != nil {
		return "", err
	}

	key := []byte(encryptionKey)
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("invalid ciphertext block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	padding := int(plainText[len(plainText)-1])
	if padding <= 0 || padding > aes.BlockSize {
		return "", errors.New("invalid padding")
	}
	for i := 0; i < padding; i++ {
		if plainText[len(plainText)-1-i] != byte(padding) {
			return "", errors.New("invalid padding content")
		}
	}

	return string(plainText[:len(plainText)-padding]), nil
}

//
// --- AES-256-CBC with Static IV (first 16 bytes of key) ---
//

func EncryptDataStaticIV(plainText, encryptionKey string) (string, error) {
	key := []byte(encryptionKey)
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	iv := key[:aes.BlockSize] // static IV from key

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	padding := aes.BlockSize - len(plainText)%aes.BlockSize
	padText := append([]byte(plainText), bytes.Repeat([]byte{byte(padding)}, padding)...)

	cipherText := make([]byte, len(padText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, padText)

	return hex.EncodeToString(cipherText), nil
}

func DecryptDataStaticIV(encryptedHex, encryptionKey string) (string, error) {
	key := []byte(encryptionKey)
	if len(key) != 32 {
		return "", errors.New("key must be 32 bytes")
	}

	iv := key[:aes.BlockSize] // static IV from key

	cipherText, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("invalid ciphertext block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, cipherText)

	padding := int(plainText[len(plainText)-1])
	if padding <= 0 || padding > aes.BlockSize {
		return "", errors.New("invalid padding")
	}
	for i := 0; i < padding; i++ {
		if plainText[len(plainText)-1-i] != byte(padding) {
			return "", errors.New("invalid padding content")
		}
	}

	return string(plainText[:len(plainText)-padding]), nil
}
