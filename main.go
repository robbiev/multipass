package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"code.google.com/p/go.crypto/pbkdf2"
	"github.com/howeyc/gopass"
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

	file, err := ioutil.ReadFile("./encryptionKeys.js")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

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
	var keys Keys
	err = json.Unmarshal(file, &keys)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", keys)

	// seems to be a null terminated string, cut off the last character
	encryptionKey, er := Base64Decode(keys.List[1].Data)

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
	key := bytez[:16] // aes key size must be 16, 24 or 32
	iv := bytez[16:] // IV byte length is equal to aes.BlockSize

	// 16 byte key, so AES-128
	b, e := DecryptAes(key, iv, encryptionKey)
	if !e {
		fmt.Println("decrypt error")
		os.Exit(1)
	}

	fmt.Println(len(b))
	fmt.Println(b)

	validationData := keys.List[1].Validation
	validation, er := base64.StdEncoding.DecodeString(validationData[0 : len(validationData)-1])
	v := DecryptData(b, validation)
	fmt.Println(len(v))
	fmt.Println(v)

	fmt.Println(bytes.Equal(b, v))

	DecryptFile(b)

	fmt.Println("done")
}

func DecryptFile(key []byte) {
	file, err := ioutil.ReadFile("/Users/robbie/Dropbox/1password/1Password.agilekeychain/data/default/2116ED1FF6AFBF230FE93AFC7DA1DBEA.1password")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	type Item struct {
		Title     string
		Encrypted string
	}

	var item Item
	err = json.Unmarshal(file, &item)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", item)

	decoded, er := Base64Decode(item.Encrypted)

	if er != nil {
		fmt.Println(er)
		os.Exit(1)
	}

	decrypted := DecryptData(key, decoded)
	fmt.Println(item.Title)
	fmt.Println(string(decrypted))
}

func Base64Decode(data string) ([]byte, error) {
  actualData := data
  if data[len(data)-1] == 0 {
    actualData = data[:len(data)-1]
  }

	decoded, err := base64.StdEncoding.DecodeString(actualData)

	if err != nil {
    return nil, err
	}

  return decoded, nil
}

func DecryptData(key, data []byte) []byte {
	// assuming salt
	salt := data[8:16]
	data = data[16:]

	// poor man's MD5 based PBKDF1
	nkey := md5.Sum(append(key, salt...))
	iv := md5.Sum(append(append(nkey[:], key...), salt...))

	// 16 byte key, so AES-128
	result, _ := DecryptAes(nkey[:], iv[:], data)

	return result
}

// https://leanpub.com/gocrypto/read#leanpub-auto-encrypting-and-decrypting-data-with-aes-cbc
// https://github.com/kisom/gocrypto/blob/master/chapter2/aescbc/aescbc.go
// Decrypt decrypts the message and removes any padding.
func DecryptAes(k, iv, in []byte) ([]byte, bool) {
	if len(in) == 0 || len(in)%aes.BlockSize != 0 {
		return nil, false
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		// potentially wrong key size, must be one of 16/24/32
		// to select AES-128, AES-192 or AES-256 respectively
		return nil, false
	}

	// iv must be == aes.BlockSize
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(in, in)

	out := Unpad(in)
	if out == nil {
		return nil, false
	}

	return out, true
}
