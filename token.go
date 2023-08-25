package main

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"math/big"
	"strings"
	"time"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload struct {
	Id  primitive.ObjectID `json:"id"`
	Iat time.Time          `json:"iat"`
	Exp time.Time          `json:"exp"`
	Tid primitive.ObjectID `json:"tid"`
}

func generateStrongString(size int) (string, error) {
	const vocabulary = "0123456789qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM"
	result := make([]byte, size)
	for i := 0; i < size; i++ {
		number, err := rand.Int(rand.Reader, big.NewInt(int64(len(vocabulary))))
		if err != nil {
			return "", err
		}

		result[i] = vocabulary[number.Int64()]
	}

	return string(result), nil
}

func encryptToken(payload Payload, header Header, key string) string {
	strHeader, err := json.Marshal(header)
	if err != nil {
		return ""
	}

	strPayload, err := json.Marshal(payload)
	if err != nil {
		return ""
	}

	sign := hmac.New(crypto.SHA512.New, []byte(key))
	sign.Write([]byte(bytes.Join([][]byte{strHeader, strPayload}, []byte("."))))
	signup := base64.StdEncoding.EncodeToString(sign.Sum(nil))
	return fmt.Sprintf("%s.%s.%s", base64.StdEncoding.EncodeToString(strHeader), base64.StdEncoding.EncodeToString(strPayload), signup)
}

func emitTokens(userId primitive.ObjectID, lifetime int) (string, string, *Payload, error) {
	if lifetime <= 0 {
		return "", "", nil, errors.New("lifetime cannot be zero or less")
	}

	exp := time.Unix(int64(time.Now().Unix())+int64(lifetime*3600), 0)
	refreshToken, err := generateStrongString(64)
	refreshTokenId := primitive.NewObjectID()
	if err != nil {
		return "", "", nil, err
	}

	header := Header{
		Alg: "HS512",
		Typ: "JWT",
	}

	payload := Payload{
		Id:  userId,
		Iat: time.Now(),
		Exp: exp, Tid: refreshTokenId,
	}

	token := encryptToken(payload, header, refreshToken)

	return token, refreshToken, &payload, nil
}

func checkToken(token string, key string) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return false
	}

	header, err := base64.StdEncoding.DecodeString(parts[0])
	payload, err := base64.StdEncoding.DecodeString(parts[1])
	signup := parts[2]

	if err != nil {
		return false
	}

	sign := hmac.New(crypto.SHA512.New, []byte(key))
	pair := bytes.Join([][]byte{header, payload}, []byte("."))

	sign.Write(pair)
	check := base64.StdEncoding.EncodeToString([]byte(sign.Sum(nil)))
	signLen := len(check)

	if signLen != len(signup) {
		return false
	}

	result := true
	for i := 0; i < len(check); i++ {
		result = signup[i] == check[i]
	}

	return result
}
