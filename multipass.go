package multipass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"code.google.com/p/go.crypto/pbkdf2"
)

func clear(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}

type KeyChain interface {
	Open(password []byte) error
	IsOpen() bool
	Close()
	ForEachItem(callback ItemCallback) error
	Keys() map[string][]byte
}

type AgileKeyChain struct {
	dir  string
	keys map[string][]byte
}

func NewAgileKeyChain(dir string) KeyChain {
	// TODO check it is a 1Password dir
	return &AgileKeyChain{dir: dir}
}

func (chain *AgileKeyChain) Close() {
	chain.keys = nil
}

func (chain *AgileKeyChain) IsOpen() bool {
	return chain.keys != nil
}

func (chain *AgileKeyChain) Keys() map[string][]byte {
	return chain.keys
}

func (chain *AgileKeyChain) ForEachItem(callback ItemCallback) error {
	return ForEachItem(chain.dir, callback)
}

func (chain *AgileKeyChain) Open(password []byte) error {
	file, err := ioutil.ReadFile(path.Join(chain.dir, "encryptionKeys.js"))
	if err != nil {
		return err
	}

	var keys Keys
	err = json.Unmarshal(file, &keys)
	if err != nil {
		return err
	}

	//fmt.Printf("%+v\n", keys)

	keyMap := make(map[string][]byte)
	for _, passKey := range keys.List {
		err = DecryptKey(password, passKey, keyMap)
		if err != nil {
			return err
		}
	}

	chain.keys = keyMap

	return nil
}

type ItemCallback func(path string, file []byte) error

func ForEachItem(onePasswordDir string, itemCallback ItemCallback) error {
	dirListing, e := ioutil.ReadDir(onePasswordDir)
	if e != nil {
		return e
	}
	for _, f := range dirListing {
		if !f.IsDir() && path.Ext(f.Name()) == ".1password" {
			p := path.Join(onePasswordDir, f.Name())
			file, err := ioutil.ReadFile(p)
			if err != nil {
				return err
			}
			err = itemCallback(p, file)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type PassKey struct {
	// Base64 encoded encryption key, AES-128 encrypted using a PBKDF2 key
	// derived from the user's password
	Data       string
	Identifier string
	Iterations int
	Level      string
	// Base64 encoded copy of the encryption key, AES-128 encrypted by itself
	Validation string
}

type Keys struct {
	List []PassKey
}

var saltMarker []byte = []byte("Salted__")
var saltLen int = len(saltMarker)

const saltDataLen = 8

func IsSalted(encryptedData []byte) bool {
	if len(encryptedData) < saltLen {
		return false
	}

	return bytes.Equal(encryptedData[:saltLen], saltMarker)
}

func DecryptKey(pass []byte, passKey PassKey, keyMap map[string][]byte) error {
	encryptedEncryptionKey, er := Base64Decode(passKey.Data)

	if er != nil {
		fmt.Println(er)
		os.Exit(1)
	}

	var salt []byte
	if IsSalted(encryptedEncryptionKey) {
		// salt marker (8 bytes) | salt (8 bytes) | data
		skip := saltLen + saltDataLen
		salt = []byte(encryptedEncryptionKey[saltLen:skip])
		encryptedEncryptionKey = encryptedEncryptionKey[skip:]
	}

	// first 16 bytes are the key, last 16 bytes are the IV
	bytez := pbkdf2.Key(pass, salt, passKey.Iterations, aes.BlockSize*2, sha1.New)
	key := bytez[:16] // aes key size must be 16, 24 or 32
	iv := bytez[16:]  // IV byte length is equal to aes.BlockSize

	// 16 byte key, so AES-128
	b, e := DecryptAes(key, iv, encryptedEncryptionKey)
	if e != nil {
		fmt.Println("decrypt error")
		os.Exit(1)
	}

	validationData := passKey.Validation
	validation, er := base64.StdEncoding.DecodeString(validationData[0 : len(validationData)-1])
	v, _ := DecryptData(b, validation)

	if !bytes.Equal(b, v) {
		return errors.New("encryption key validation failed")
	}

	keyMap[passKey.Level] = b

	return nil
}

type Item struct {
	Title    string
	Payload  string
	TypeName string
}

func DecryptFile(file []byte, keyMap map[string][]byte) (Item, error) {
	type EncryptedItem struct {
		Title     string
		Encrypted string

		// determine which encryption key to use; values are SL3 or SL5 in my keychain
		// currently we assume SL5 if this field is empty
		// TODO add openContents.securityLevel field, it seems to be an altenative
		SecurityLevel string

		// Known values (there are probably others):
		//   passwords.Password
		//   webforms.WebForm
		//   system.folder.SavedSearch
		//   securenotes.SecureNote
		//   wallet.financial.CreditCard
		//   wallet.computer.License
		//   identities.Identity
		TypeName string
	}

	var item EncryptedItem
	err := json.Unmarshal(file, &item)
	if err != nil {
		return Item{}, err
	}

	//fmt.Printf("%+v\n", item)

	decoded, er := Base64Decode(item.Encrypted)

	if er != nil {
		return Item{}, er
	}

	securityLevel := item.SecurityLevel
	if len(securityLevel) == 0 {
		securityLevel = "SL5"
	}

	decrypted, e := DecryptData(keyMap[securityLevel], decoded)

	if e != nil {
		return Item{}, e
	}

	return Item{Title: item.Title, Payload: string(decrypted), TypeName: item.TypeName}, nil
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

func DecryptData(key, data []byte) ([]byte, error) {
	if !IsSalted(data) {
		return nil, errors.New("unsalted data not supported")
	}

	// assuming salt
	salt := data[saltLen : saltLen+saltDataLen]
	data = data[saltLen+saltDataLen:]

	// poor man's MD5 based PBKDF1
	nkey := md5.Sum(append(key, salt...))
	iv := md5.Sum(append(append(nkey[:], key...), salt...))

	// 16 byte key, so AES-128
	result, err := DecryptAes(nkey[:], iv[:], data)

	if err != nil {
		fmt.Println("decryption error")
		return nil, err
	}

	return result, nil
}

// https://leanpub.com/gocrypto/read#leanpub-auto-encrypting-and-decrypting-data-with-aes-cbc
// https://github.com/kisom/gocrypto/blob/master/chapter2/aescbc/aescbc.go
// Decrypt decrypts the message and removes any padding.
func DecryptAes(k, iv, in []byte) ([]byte, error) {
	if len(in) == 0 || len(in)%aes.BlockSize != 0 {
		return nil, errors.New("input block size not a multiple of aes.BlockSize")
	}

	c, err := aes.NewCipher(k)
	if err != nil {
		// potentially wrong key size, must be one of 16/24/32
		// to select AES-128, AES-192 or AES-256 respectively
		return nil, err
	}

	// iv must be == aes.BlockSize
	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(in, in)

	out := Unpad(in)
	if out == nil {
		return nil, errors.New("failed to remove padding")
	}

	return out, nil
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
