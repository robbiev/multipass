package main

import (
	"bytes"
	"code.google.com/p/go.crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/howeyc/gopass"
	"io/ioutil"
	"os"
)

func clear(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}

// Pad applies the PKCS #7 padding scheme on the buffer.
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

// Unpad strips the PKCS #7 padding on a buffer. If the padding is
// invalid, nil is returned.
func Unpad(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}

	padding := in[len(in)-1]
	fmt.Printf("len %s\n", len(in))
	fmt.Printf("padding %s\n", padding)
	if int(padding) > len(in) || padding > aes.BlockSize {
		return nil
	} else if padding == 0 {
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
			return nil
		}
	}
	return in[:len(in)-int(padding)]
}

func main() {
	fmt.Printf("Password: ")
	pass := gopass.GetPasswd()
	defer clear(pass)

	type PassKey struct {
		Data       string
		Identifier string
		Iterations int
		Level      string
		Validation string
	}
	type Keys struct {
		List []PassKey
	}
	file, err := ioutil.ReadFile("./encryptionKeys.js")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var keys Keys
	err = json.Unmarshal(file, &keys)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", keys)

	data := keys.List[1].Data

	// seems to be a null terminated string, cut off the last character
	encryptionKey, er := base64.StdEncoding.DecodeString(data[0 : len(data)-1])

	if er != nil {
		fmt.Println(er)
		os.Exit(1)
	}

	saltMarker := []byte("Salted__")
	salted := (bytes.Equal([]byte(encryptionKey[0:len(saltMarker)]), saltMarker))

	var salt []byte
	if salted {
		// salt marker (8 bytes) | salt (8 bytes) | data
		skip := len(saltMarker) + 8
		salt = []byte(encryptionKey[len(saltMarker):skip])
		encryptionKey = encryptionKey[skip:]
	}

	// first 16 bytes are the key, last 16 bytes are the IV
	bytez := pbkdf2.Key(pass, salt, keys.List[1].Iterations, aes.BlockSize*2, sha1.New)
	key := bytez[:16]
	iv := bytez[16:]

	b, e := Decryptr(key, iv, encryptionKey)
	if !e {
		fmt.Println("decrypt error")
		os.Exit(1)
	}

	fmt.Println(len(b))
	fmt.Println(b)

	validationData := keys.List[1].Validation
	validation, er := base64.StdEncoding.DecodeString(validationData[0 : len(validationData)-1])
	v := decryptData(b, validation)
	fmt.Println(len(v))
	fmt.Println(v)

	fmt.Println(bytes.Equal(b, v))

	decryptFile(b)

	fmt.Println("done")
}

func decryptFile(key []byte) {
	type Item struct {
		Title     string
		Encrypted string
	}
	file, err := ioutil.ReadFile("/Users/robbie/Dropbox/1password/1Password.agilekeychain/data/default/2116ED1FF6AFBF230FE93AFC7DA1DBEA.1password")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var item Item
	err = json.Unmarshal(file, &item)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", item)

	data := item.Encrypted
	decoded, er := base64.StdEncoding.DecodeString(data[0 : len(data)-1])

	if er != nil {
		fmt.Println(er)
		os.Exit(1)
	}

	decrypted := decryptData(key, decoded)
	fmt.Println(item.Title)
	fmt.Println(string(decrypted))
}

func decryptData(key, data []byte) []byte {
	// assuming salt
	salt := data[8:16]
	data = data[16:]
	nkey := md5.Sum(append(key, salt...))
	iv := md5.Sum(append(append(nkey[:], key...), salt...))

	result, _ := Decryptr(nkey[:], iv[:], data)
	return result
}

// https://leanpub.com/gocrypto/read#leanpub-auto-encrypting-and-decrypting-data-with-aes-cbc
// https://github.com/kisom/gocrypto/blob/master/chapter2/aescbc/aescbc.go
// Decrypt decrypts the message and removes any padding.
func Decryptr(k, iv, in []byte) ([]byte, bool) {
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, false
	}

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(in, in)
	out := Unpad(in)
	if out == nil {
		return nil, false
	}
	return out, true
}
