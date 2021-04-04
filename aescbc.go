package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"github.com/git-yongge/crypto-sha3"
)

const (
	HashSize  = 32
	BlockSize = aes.BlockSize
)

var (
	ErrPassword   = errors.New("wrong password")
	ErrCipherText = errors.New("ciphertext too short")
	ErrPassEmpty  = errors.New("password cannot be empty")
	ErrDecrypt    = errors.New("could not decrypt key with given password")
)

// AesCBCEncrypt CBC模式加密
func AesCBCEncrypt(origData []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrPassEmpty
	}

	key16 := make([]byte, 16)
	copy(key16, key)
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}

	hash := sha3.Keccak256(origData)
	blockSize := block.BlockSize()
	origData = pkcs5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key16[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	hash = append(hash, crypted...)
	return hash, nil
}

// AesCBCDecrypt CBC模式解密，校验密码
func AesCBCDecrypt(encrypted []byte, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, ErrPassEmpty
	}

	key16 := make([]byte, 16)
	copy(key16, key)

	hash := encrypted[:HashSize]
	encrypted = encrypted[HashSize:]

	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key16[:blockSize])
	origData := make([]byte, len(encrypted))
	blockMode.CryptBlocks(origData, encrypted)
	origData = pkcs5UnPadding(origData)
	if bytes.Equal(hash, sha3.Keccak256(origData)) {
		return origData, nil
	}
	return nil, ErrPassword
}

// AesCBCEncryptToBase64 加密成base64格式秘钥
func AesCBCEncryptToBase64(origData string, key string) (string, error) {
	bytes, err := AesCBCEncrypt([]byte(origData), []byte(key))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// AesCBCDecryptFromBase64 base64形式秘钥解密
func AesCBCDecryptFromBase64(encrypted string, key string) (string, error) {
	decodeString, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	bytes, err := AesCBCDecrypt(decodeString, []byte(key))
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// AesRawCBCEncrypt CBC模式加密
func AesRawCBCEncrypt(origData []byte, key []byte) ([]byte, error) {

	key16 := make([]byte, 16)
	copy(key16, key)
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	origData = pkcs5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key16[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

// AesRawCBCDecrypt 不校验密码解密
func AesRawCBCDecrypt(key, cipherText, iv []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypter := cipher.NewCBCDecrypter(aesBlock, iv)
	paddedPlaintext := make([]byte, len(cipherText))
	decrypter.CryptBlocks(paddedPlaintext, cipherText)
	plaintext := pkcs7Unpad(paddedPlaintext)
	if plaintext == nil {
		return nil, ErrDecrypt
	}
	return plaintext, err
}
