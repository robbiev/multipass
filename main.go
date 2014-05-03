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
		return nil
	}

	padding := in[len(in)-1]
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
	fmt.Println(string(pass))

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

  var salt []byte
  if salted {
    // salt marker (8 bytes) | salt (16 bytes) | data
    skip := len(saltMarker) + 16
    salt = []byte(encryptionKey[len(saltMarker):skip])
    encryptionKey = encryptionKey[skip:len(encryptionKey)-skip]
  }

  bytez := pbkdf2.Key(pass, salt, keys.List[1].Iterations, sha1.Size, sha1.New)
  fmt.Println(len(bytez))

  // https://leanpub.com/gocrypto/read#leanpub-auto-encrypting-and-decrypting-data-with-aes-cbc
  // https://github.com/kisom/gocrypto/blob/master/chapter2/aescbc/aescbc.go
  aes128KeySize := 16
  key := bytez[0:aes128KeySize]
  iv := bytez[aes128KeySize:len(bytez)]

  fmt.Println("done")
}
