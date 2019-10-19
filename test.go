package main

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"net/http"
	"sync"
	"time"
)
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}


const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(
	rand.NewSource(time.Now().UnixNano()))

func StringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func String(length int) string {
	return StringWithCharset(length, charset)
}

func main() {
	var wg sync.WaitGroup
	for i:= 0; i < 100; i++ {
		wg.Add(1)
		go send(&wg)
		time.Sleep(100 * time.Millisecond)
	}
	wg.Wait()
}
func send(wg *sync.WaitGroup) {
	defer wg.Done()
	u := User{
		Username: String(6),
		Password: "12345",
	}
	request ,_ := json.Marshal(u)
	resp, err := http.Post("http://127.0.0.1:8080/register", "application/json", bytes.NewBuffer(request))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

