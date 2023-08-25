package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	client, err := connect(os.Getenv("DB"))
	if err != nil {
		log.Fatal(err)
	}

	DB = client

	http.HandleFunc("/createUser", createUserHandler)
	http.HandleFunc("/createToken", emitTokensHandler)
	http.HandleFunc("/refreshToken", refreshTokenHandler)

	port, err := strconv.ParseInt(os.Getenv("PORT"), 10, 64)
	if err != nil {
		log.Fatal(err.Error())
	}

	err = http.ListenAndServe(fmt.Sprintf(":%d", port), nil)

}
