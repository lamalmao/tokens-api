package main

import (
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"log"
	"math"
	"net/http"
	"strings"
	"time"
)

func sendError(w http.ResponseWriter, msg string, statusCode int) {
	w.WriteHeader(statusCode)

	r, _ := json.Marshal(ErrResponse{Error: msg})
	_, err := w.Write(r)
	if err != nil {
		log.Println(err.Error())
	}
}

type ErrResponse struct {
	Error string `json:"error"`
}

type UserCreated struct {
	Id string `json:"id"`
}

func createUserHandler(writer http.ResponseWriter, _ *http.Request) {
	var r []byte

	instance, err := createUser(DB)
	if err != nil {
		r, _ = json.Marshal(ErrResponse{Error: err.Error()})
	} else {
		r, _ = json.Marshal(UserCreated{Id: instance.userId.Hex()})
	}

	writer.Header().Set("Content-Type", "application/json")
	_, err = writer.Write(r)
	if err != nil {
		log.Println(err.Error())
	}
}

type EmitTokensRequest struct {
	UserId               string `json:"User"`
	AccessTokenLifeTime  int    `json:"accessTokenLifeTime"`
	RefreshTokenLifeTime int    `json:"refreshTokenLifeTime"`
}

type EmitTokensResponse struct {
	AccessToken  string `json:"token"`
	RefreshToken string `json:"refreshToken"`
}

func emitTokensHandler(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	if strings.ToLower(request.Method) != "post" {
		sendError(writer, "Use POST request method for this endpoint", 400)
		return
	}

	var body EmitTokensRequest
	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&body)
	if err != nil {
		sendError(writer, err.Error(), 400)
		return
	}

	userId, _ := primitive.ObjectIDFromHex(body.UserId)
	token, key, err := createTokenPair(DB, userId, body.AccessTokenLifeTime, body.RefreshTokenLifeTime)
	if err != nil {
		sendError(writer, err.Error(), 401)
		return
	}

	response, err := json.Marshal(EmitTokensResponse{AccessToken: token, RefreshToken: key})
	if err != nil {
		sendError(writer, err.Error(), 500)
		return
	}

	_, err = writer.Write(response)
	if err != nil {
		log.Println(err.Error())
	}
}

type RefreshTokenRequest struct {
	Token string `json:"accessToken"`
	Key   string `json:"refreshToken"`
}

type RefreshTokenResponse struct {
	Token string `json:"accessToken"`
}

func refreshTokenHandler(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json")

	if strings.ToLower(request.Method) != "post" {
		sendError(writer, "Use POST request method for this endpoint", 400)
		return
	}

	var body RefreshTokenRequest
	decoder := json.NewDecoder(request.Body)
	err := decoder.Decode(&body)
	if err != nil {
		sendError(writer, err.Error(), 400)
		return
	}

	check, refresh, payload := verifyToken(DB, body.Token)
	if !check {
		sendError(writer, "Invalid token", 401)
		return
	}

	if refresh.validUntil.Unix() < time.Now().Unix() {
		sendError(writer, "Refresh token outdated", 401)
		return
	}

	if refresh.Value != body.Key {
		sendError(writer, "Invalid refresh token", 401)
		return
	}

	diff := int(math.Ceil(float64(payload.Exp.Unix()-payload.Iat.Unix()) / 3600))
	newPayload := Payload{
		Id:  payload.Id,
		Iat: time.Now(),
		Exp: time.Unix(int64(time.Now().Unix())+int64(diff*3600), 0),
		Tid: payload.Tid,
	}

	newToken := encryptToken(newPayload, Header{Alg: "HS512", Typ: "JWT"}, refresh.Value)

	result, err := json.Marshal(RefreshTokenResponse{Token: newToken})
	if err != nil {
		sendError(writer, err.Error(), 500)
		return
	}

	_, err = writer.Write(result)
	if err != nil {
		log.Println(err.Error())
	}
}
