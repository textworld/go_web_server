package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

type EncryptedUser struct {
	Name string `json:"name"`
	Password string `json:"password"`
}

func CreateToken(userid uint64) (string, error) {
	var err error
	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = userid
	atClaims["exp"] = time.Now().Add(time.Hour * 15).Unix()
	at := jwt.NewWithClaims(jwt.SigningMethodHS256, atClaims)
	token, err := at.SignedString([]byte("es_server_token_key"))
	if err != nil {
		return "", err
	}
	return token, nil
}
func Login(c *gin.Context) {
	var u EncryptedUser
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "Invalid json provided")
		return
	}

	privateKeyPath := "/Users/aside/.ssh/zwb_rsa"
	privateKey, err := GetPrivateKey(privateKeyPath)
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

	if string(des) != "zzz" {
		c.JSON(200, gin.H{"code": 4000, "message": "authentication failure"})
		return
	}

	token, err := CreateToken(1)
	if err != nil {
		panic(err)
	}

	c.JSON(200, gin.H{"code": 2000, "message": "success login", "data": gin.H{
		"token": token,
	}})
}
