package main

import (
	"encoding/json"
	"encoding/base64"
  "io/ioutil"
	"fmt"
  "os"
  "bytes"
	"github.com/howeyc/gopass"
  "code.google.com/p/go.crypto/pbkdf2"
  "crypto/sha1"
  "crypto/aes"
  "crypto/cipher"
)

func clear(b []byte) {
  for i := 0; i < len(b); i++ {
    b[i] = 0;
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
    fmt.Println("x1")
		return nil
	}

	padding := in[len(in)-1]
  fmt.Printf("len %s\n", len(in))
  fmt.Printf("padding %s\n", padding)
	if int(padding) > len(in) || padding > aes.BlockSize {
    fmt.Println("x2")
		return nil
	} else if padding == 0 {
    fmt.Println("x3")
		return nil
	}

	for i := len(in) - 1; i > len(in)-int(padding)-1; i-- {
		if in[i] != padding {
    fmt.Println("x4")
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
    Data string
    Identifier string
    Iterations int
    Level string
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
  encryptionKey, er := base64.StdEncoding.DecodeString(data[0:len(data)-1])

  if er != nil {
    fmt.Println(er)
    os.Exit(1)
  }

  saltMarker := []byte("Salted__")
  salted := (bytes.Equal([]byte(encryptionKey[0:len(saltMarker)]), saltMarker))
  fmt.Println(encryptionKey[0:30])
  fmt.Println(len(encryptionKey))

  var salt []byte
  if salted {
    // salt marker (8 bytes) | salt (8 bytes) | data
    skip := len(saltMarker) + 8
    salt = []byte(encryptionKey[len(saltMarker):skip])
    //encryptionKey = encryptionKey[skip:len(encryptionKey)-skip]
    encryptionKey = encryptionKey[skip:]
  }

  fmt.Println(encryptionKey[0:30])
  fmt.Println(len(encryptionKey))
  fmt.Println(len(salt))

  bytez := pbkdf2.Key(pass, salt, keys.List[1].Iterations, aes.BlockSize * 2, sha1.New)
  fmt.Println(len(bytez))
  fmt.Println(bytez)

  //b, e := Decrypt(bytez[:16], bytez[16:], encryptionKey)
  b, e := Decrypt(bytez, encryptionKey)
  if !e {
    fmt.Println("decrypt error")
    os.Exit(1)
  }

  fmt.Println(len(b))

  validationData := keys.List[1].Validation
  validation, er := base64.StdEncoding.DecodeString(validationData[0:len(validationData)-1])
  fmt.Println(validation[:8])

  fmt.Println("done")
}

func Decrypt(k, in []byte) ([]byte, bool) {
  if len(in) == 0 || len(in)%aes.BlockSize != 0 {
    fmt.Println("meh")
    return nil, false
  }

  c, err := aes.NewCipher(k)
  if err != nil {
    fmt.Println("meh2")
    return nil, false
  }

  cbc := cipher.NewCBCDecrypter(c, in[:aes.BlockSize])
  cbc.CryptBlocks(in[aes.BlockSize:], in[aes.BlockSize:])
  out := in[aes.BlockSize:]
  if out == nil {
    fmt.Println("meh3")
    return nil, false
  }
  return out, true

}

// https://leanpub.com/gocrypto/read#leanpub-auto-encrypting-and-decrypting-data-with-aes-cbc
// https://github.com/kisom/gocrypto/blob/master/chapter2/aescbc/aescbc.go
// Decrypt decrypts the message and removes any padding.
// func Decrypt(k, iv, in []byte) ([]byte, bool) {
// 	c, err := aes.NewCipher(k)
// 	if err != nil {
//     fmt.Println("meh2")
// 		return nil, false
// 	}

// 	cbc := cipher.NewCBCDecrypter(c, iv)
// 	cbc.CryptBlocks(in, in)
//   fmt.Println("decrypted")
//   fmt.Println(len(in))
// 	out := Unpad(in)
// 	if out == nil {
//     fmt.Println("meh3")
// 		return nil, false
// 	}
// 	return out, true

// }
