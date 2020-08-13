package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)
func AESCTR(text, key, iv string) (string, error) {
	keyBs, _ := hex.DecodeString(key)
	ivBs, _ := hex.DecodeString(iv)

	plaintext := []byte(text)
	block, err := aes.NewCipher(keyBs)
	if err != nil {
		return "", fmt.Errorf("failed to new cipher: %v", err)
	}

	ciphertext := make([]byte, len(plaintext))

	stream := cipher.NewCTR(block, ivBs)
	stream.XORKeyStream(ciphertext, plaintext)
	return hex.EncodeToString(ciphertext), nil
}

//js 方案 https://github.com/travist/jsencrypt

// ssh-keygen -m PEM -t rsa -b 4096
func GetPrivateKey(path string)(*rsa.PrivateKey, error){
	priv, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}

	privPem, _ := pem.Decode(priv)
	if privPem == nil {
		return nil, fmt.Errorf("failed to decode private content")
	}

	var privPemBytes []byte
	if privPem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("no rsa private key found, but got %s", privPem.Type)
	}

	privPemBytes = privPem.Bytes

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		panic(err)
	}
	privPemBytes = privPem.Bytes

	var privateKey *rsa.PrivateKey
	var ok bool
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to cast key to type *rsa.PrivateKey")
	}

	return privateKey, nil
}

func GetPublicKey(rsaPublicKeyLocation string) (*rsa.PublicKey, error){
	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		return nil, fmt.Errorf("PublicKeyLocation %s was not found", rsaPublicKeyLocation)
	}
	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return nil, fmt.Errorf("failed to decode public key")
	}
	//if pubPem.Type != "RSA PUBLIC KEY" {
	//	return nil, fmt.Errorf("no RSA public key found, but got %s", pubPem.Type)
	//}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	var ok bool
	var pubKey *rsa.PublicKey
	if pubKey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("failed to parse public key")
	}

	return pubKey, nil
}

func DecryptOAEP(cipherText string, privKey rsa.PrivateKey)  (string) {
	ct,_ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")

	// crypto/rand.Reader is a good source of entropy for blinding the RSA
	// operation.
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from decryption: %s\n", err)
		return "Error from Decryption";
	}
	fmt.Printf("Plaintext: %s\n", string(plaintext))

	return string(plaintext)
}


