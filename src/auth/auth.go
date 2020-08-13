package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-ldap/ldap/v3"
	"net/http"
	"os"
	"strings"
	"time"
)

type EncryptedUser struct {
	Name string `json:"name"`
	Password string `json:"password"`
}

type Middleware struct {
	accessToken string
	privateKeyPath string
}

func NewMiddleware(accessToken, privateKeyPath string) (*Middleware, error) {
	if len(strings.TrimSpace(accessToken)) == 0 {
		return nil, fmt.Errorf("accessToken can not be empty")
	}

	_, err := os.Stat(privateKeyPath)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("privateKeyPath: %s is not exist")
		}
		return nil, err
	}

	return &Middleware{
		accessToken:    strings.TrimSpace(accessToken),
		privateKeyPath: privateKeyPath,
	}, nil
}

func (m *Middleware) CreateToken(username string) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["username"] = username
	atClaims["exp"] = time.Now().Add(time.Hour * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte(m.accessToken))
	if err != nil {
		return "", err
	}
	return token, nil
}
func (m *Middleware) Login(c *gin.Context) {
	var u EncryptedUser
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	privateKey, err := GetPrivateKey(m.privateKeyPath)
	if err != nil {
		panic("failed to get private key")
	}

	bs, err := hex.DecodeString(u.Password)
	if err != nil {
		c.JSON(200, gin.H{"code": 4000, "message": "incorrect password format"})
		return
	}
	des, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, bs)
	if err != nil {
		c.JSON(200, gin.H{"code": 5000, "message": err.Error()})
		return
	}

	if pass, err := ldapVerity(u.Name, string(des)); err != nil {
		panic(err)
	}else if !pass {
		c.JSON(200, gin.H{"code": 4000, "message": "authentication failed"})
		return
	}

	token, err := m.CreateToken(u.Name)
	if err != nil {
		panic(err)
	}

	c.JSON(200, gin.H{"code": 2000, "message": "success login", "data": gin.H{
		"token": token,
	}})
}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	//normally Authorization the_token_xxx
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func (m *Middleware) VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenString := ExtractToken(r)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		//Make sure that the token method conform to "SigningMethodHMAC"
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(m.accessToken), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (m *Middleware) TokenValid(r *http.Request) error {
	token, err := m.VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		return err
	}
	return nil
}

func (m *Middleware) TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := m.TokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, err.Error())
			c.Abort()
			return
		}
		c.Next()
	}
}


func ldapVerity(username, password string) (bool, error){
	l, err := ldap.Dial("tcp", "10.0.80.254:389")
	if err != nil {
		return false, err
	}
	defer l.Close()

	err = l.Bind("blj", "4SkeobpBS1EWzNvb")
	if err != nil {
		return false, err
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
		return false, err
	}

	if len(sr.Entries) != 1 {
		return false, nil
	}

	userdn := sr.Entries[0].DN

	err = l.Bind(userdn, password)
	if err != nil {
		return false, nil
	}

	return true, nil
}