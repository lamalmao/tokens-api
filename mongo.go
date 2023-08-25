package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"os"
	"strings"
	"time"
)

var DB *mongo.Client

func connect(address string) (*mongo.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(address))

	if err != nil {
		return nil, err
	}

	return client, nil
}

type User struct {
	userId   primitive.ObjectID `bson:"_id,omitempty"`
	joinDate time.Time
}

type Token struct {
	tokenId    primitive.ObjectID `bson:"_id,omitempty"`
	User       primitive.ObjectID `bson:"user"`
	Value      string             `bson:"value"`
	validUntil time.Time          `bson:"validUntil"`
	issueDate  time.Time
}

func createUser(client *mongo.Client) (*User, error) {
	users := client.Database(os.Getenv("BASE")).Collection("users")
	if users == nil {
		return nil, errors.New("cannot connect to database collection")
	}

	var id = primitive.NewObjectID()
	var date = time.Now()
	_, err := users.InsertOne(context.TODO(), bson.D{
		{"_id", id},
		{"joinDate", date},
	})
	if err != nil {
		return nil, err
	}

	result := User{userId: id, joinDate: date}
	return &result, nil
}

func createTokenPair(client *mongo.Client, userId primitive.ObjectID, accessTokenLifetime int, refreshTokenLifeTime int) (string, string, error) {
	db := client.Database(os.Getenv("BASE"))
	users := db.Collection("users")
	if users == nil {
		return "", "", errors.New("cannot connect to database collection")
	}

	found, err := users.CountDocuments(context.TODO(), bson.D{
		{"_id", userId},
	})
	if err != nil {
		return "", "", err
	}
	if found == 0 {
		return "", "", errors.New("user not found")
	}

	tokens := db.Collection("tokens")
	accessToken, refreshToken, payload, err := emitTokens(userId, accessTokenLifetime)
	if err != nil {
		return "", "", err
	}

	lifetime := time.Unix(time.Now().Unix()+int64(refreshTokenLifeTime*3600), 0)
	_, err = tokens.InsertOne(context.TODO(), bson.D{
		{"_id", payload.Tid},
		{"validUntil", lifetime},
		{"User", userId},
		{"Value", refreshToken},
	})
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func verifyToken(client *mongo.Client, token string) (bool, *Token, *Payload) {
	db := client.Database(os.Getenv("BASE"))
	tokens := db.Collection("tokens")

	parts := strings.Split(token, ".")
	if len(parts) < 3 {
		return false, nil, nil
	}

	var payload Payload
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		fmt.Println(err)
		return false, nil, nil
	}

	err = json.Unmarshal(raw, &payload)
	if err != nil {
		fmt.Println(err)
		return false, nil, nil
	}

	var data Token
	err = tokens.FindOne(context.TODO(), bson.D{
		{"_id", payload.Tid},
	}).Decode(&data)
	if err != nil {
		fmt.Println(err)
		return false, nil, nil
	}

	return checkToken(token, data.Value), &data, &payload
}
