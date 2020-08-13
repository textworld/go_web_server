package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"testing"
)

// openssl rsa -in mykey.pem -pubout > mykey.pub
func TestGetPublicKey(t *testing.T) {
	publicKey, err := GetPublicKey("/Users/aside/.ssh/zwb_rsa.pem.pub")
	if err != nil {
		t.Fatal(err)
	}

	res, err :=rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte("XIAOyan2222"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(hex.EncodeToString(res))

	privateKey, err := GetPrivateKey("/Users/aside/.ssh/zwb_rsa")
	if err != nil {
		t.Fatal(err)
	}

	des, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, res)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("des %s", string(des))
}

func TestGetPrivateKey(t *testing.T) {
	privateKey, err := GetPrivateKey("/Users/aside/.ssh/zwb_rsa")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("size: %d", privateKey.Size())
}

