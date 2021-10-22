package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	qrencode "github.com/skip2/go-qrcode"
)

const key = "boobacabcoffee33"

var aesgcm cipher.AEAD

var ciphertext []byte

type Data struct {
	Text string    `json:"text"`
	CreationStamp time.Time `json:"stamp"`
	TtlSeconds  uint64 `json:"ttl"`
}

func createCipher(str []byte) {

	encryptText := encrypt(str, key)

	file, err := os.Create("sample.txt")
	if err != nil{
		fmt.Println("Unable to create file:", err)
		os.Exit(1)
	}
	file.WriteString(string(encryptText))
}

func createData(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")

	var data Data

	ttl, err := strconv.ParseUint(r.URL.Query().Get("ttl"), 10, 64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, err.Error())
		return
	}

	var buf []byte
	buf, err = io.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("err: %v", err)
	}
	data.Text = string(buf)
	data.TtlSeconds = ttl
	data.CreationStamp = time.Now()

	dataStr, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, err.Error())
		return
	}

	createCipher(dataStr)

	qrStr, err := qrencode.Encode(string(dataStr), qrencode.Medium, 256)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, err.Error())
		return
	}
	//
	_, _ = base64.NewEncoder(base64.StdEncoding, w).Write(qrStr)
	w.WriteHeader(http.StatusOK)
}

func validateData(w http.ResponseWriter, r *http.Request) {

	encodedStr, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, err.Error())
		return
	}
	jsonText := decrypt(encodedStr, key)

	var decryptedData Data
	err = json.Unmarshal(jsonText, &decryptedData)

	isValid := time.Now().Before(decryptedData.CreationStamp.Add(time.Second * time.Duration(decryptedData.TtlSeconds)))
	if !isValid {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(decryptedData.Text))
	}
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, pass string) []byte {
	block, _ := aes.NewCipher([]byte(createHash(pass)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, pass string) []byte {
	key := []byte(createHash(pass))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return plaintext
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/data", createData).Methods("POST")
	r.HandleFunc("/data", validateData).Methods("VALID")
	log.Fatal(http.ListenAndServe(":8000", r))
}
