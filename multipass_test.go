package multipass

import (
	"fmt"
	"os"
	"path"
	"testing"
	//"github.com/howeyc/gopass"
)

func TestKeyChain(*testing.T) {
	//fmt.Printf("Password: ")
	//pass := gopass.GetPasswd()

	pass := []byte(os.Getenv("AGILE_PWD"))
	home := os.Getenv("HOME")
	onePasswordDir := path.Join(home, "/Dropbox/1password/1Password.agilekeychain/data/default")

	keyChain := NewAgileKeyChain(onePasswordDir)
	defer keyChain.Close()
	keyChain.Open(pass)

	keyChain.ForEachItem(func(p string, f []byte) error {
		fmt.Println("====")
		fmt.Println(p)
		item, err := DecryptFile(f, keyChain.Keys())
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println(item.Title)
			fmt.Println(item.TypeName)
			//fmt.Println(item.Payload)
		}
		return nil
	})

	fmt.Println("done")

}
