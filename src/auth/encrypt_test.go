package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"testing"
)

// openssl rsa -in mykey.pem -pubout > mykey.pub
func TestGetPublicKey(t *testing.T) {
	publicKey, err := GetPublicKey("/Users/aside/.ssh/zwb_rsa.pem.pub")
	if err != nil {
		t.Fatal(err)
	}

	res, err :=rsa.EncryptPKCS1v15(rand.Reader, publicKey, []byte("zzz"))
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

func TestDia(t *testing.T) {
	l, err := ldap.Dial("tcp", "10.0.80.254:389")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = l.Bind("blj", "T9lpUvUfWy5pJ1G4JSqEH5dvPiQhn2GTQslpTadVU50=")
	if err != nil {
		t.Fatal(err)
	}

	searchRequest := ldap.NewSearchRequest(
		"OU=U51,DC=51,DC=nb",
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&(objectClass=person)(sAMAccountName=%s))", username),
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}

	if len(sr.Entries) != 1 {
		t.Fatal("failed")
	}

	userdn := sr.Entries[0].DN

	err = l.Bind(userdn, password)
	if err != nil {

	}
}