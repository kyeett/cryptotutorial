package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/google/uuid"
)

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func hash(data []byte) []byte {
	s := sha1.Sum(data)
	return s[:]
}

func PublicVerify(key *rsa.PublicKey, sign, data []byte) error {
	return rsa.VerifyPKCS1v15(key, crypto.SHA1, hash(data), sign)
}

func main() {
	bitSize := 2048
	key, err := rsa.GenerateKey(rand.Reader, bitSize)
	checkError(err)

	data := []byte(uuid.New().String())
	label := []byte("")
	signedData, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, data, label)
	checkError(err)

	if err := PublicVerify(&key.PublicKey, signedData, data); err != nil {
		log.Fatalf("verification of data failed: %s", err)
	}

	otherData := []byte(uuid.New().String())
	if err := PublicVerify(&key.PublicKey, signedData, otherData); err != nil {
		log.Fatalf("verification of otherData failed: %s", err)
	}

	// fmt.Println(string(savePrivateKeyToMemory(key)))
	// fmt.Println(string(savePublicKeyToMemory(key)))
}

func savePrivateKeyToMemory(key *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PrivateKey(key)
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	return pem.EncodeToMemory(&privBlock)
}

func savePublicKeyToMemory(key *rsa.PrivateKey) []byte {
	privDER := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	privBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	return pem.EncodeToMemory(&privBlock)
}
