package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
	_ "github.com/lib/pq"
)
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type Header struct {
	Type string	`json:"type"`
	Alg string `json:"alg"`
}
type Claims struct {
	Exp int64 `json:"exp"`
	Iss string `json:"iss"`
	Aud string	`json:"aud"`
	Type string `json:"type"`
	Data interface{} `json:"data"`
}
var keySecret = "123"
var Db *sql.DB

func init() {
	var err error
	Db, err = sql.Open("postgres", "user=postgres dbname=postgres password=postgres sslmode=disable")
	if err != nil {
		panic(err)
	}

}
func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if user.Username == "" || user.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Username/password is required"))
			return;
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var count int
		err = Db.QueryRow("select count(*) from users where username = $1", user.Username).Scan(&count)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if count > 0 {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte("username is already exist"))
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
		rows, err := Db.Query("insert into users (username, password) values ($1, $2)", user.Username, string(hashedPassword))
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Println(err.Error())
			return
		}
		defer rows.Close()
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}


}
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var user User
		err := json.NewDecoder(r.Body).Decode(&user)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if user.Username == "" || user.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("Username/password is required"))
			return;
		}
		var userDB User

		err = Db.QueryRow("select password from users where username = $1", user.Username).Scan(&userDB.Password)
		if err != nil {
			if err == sql.ErrNoRows {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err = bcrypt.CompareHashAndPassword([]byte(userDB.Password), []byte(user.Password)); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(5 * time.Minute)
		claims := Claims{
			Exp: expirationTime.Unix(),
			Data: user.Username,
		}
		tokens, err:= SignedString(claims)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write([]byte(tokens))
		return
	} else {
		w.WriteHeader(http.StatusNotFound)
		return
	}

}
func SignedString(claims Claims) (string, error) {
	header := Header{
		Type: "JWT",
		Alg: "HS256",
	}
	headerJson, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerStr := base64.URLEncoding.EncodeToString(headerJson)

	claimsJson, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	claimsStr := base64.URLEncoding.EncodeToString(claimsJson)

	h := hmac.New(sha256.New, []byte(keySecret))
	h.Write([]byte(headerStr + "." + claimsStr))
	shaStr := base64.URLEncoding.EncodeToString(h.Sum(nil))

	return headerStr + "." + claimsStr + "." + shaStr, nil
}
func main() {

	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/login", loginHandler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
