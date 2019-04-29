package main

import (
	"fmt"
	"syscall/js"
	"encoding/hex"

	paillier "github.com/Roasbeef/go-go-gadget-paillier"
)

// Global
var privKey *paillier.PrivateKey

func generateKeysJS(bits int) map[string]interface{} {
	k := make(map[string]interface{})
	var err error
	privKey, err = generateKeys(bits)
	if err != nil {
		fmt.Println(err)
		return k
	}

	k["n"] = fmt.Sprintf("%x", privKey.PublicKey.N)
	k["lambda"] = fmt.Sprintf("%x", privKey.PublicKey.G)

	return k
}

func encryptJS(i int) string {
	ei, err := encrypt(&privKey.PublicKey, i)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	return fmt.Sprintf("%x", ei)
}


func decryptJS(eis string) int {
	ei, errDS := hex.DecodeString(eis)
	if errDS != nil {
		fmt.Println(errDS)
		return 0
	}
	i, errD := decrypt(privKey, ei)
	if errD != nil {
		fmt.Println(errD)
		return 0
	}
	return i
}

func addJS(eas, ebs string) string {
	eab, errADS := hex.DecodeString(eas)
	if errADS != nil {
		fmt.Println(errADS)
		return ""
	}
	ebb, errBDS := hex.DecodeString(ebs)
	if errBDS != nil {
		fmt.Println(errBDS)
		return ""
	}
	return fmt.Sprintf("%x", add(&privKey.PublicKey, eab, ebb))
}

func multJS(eis string, b int) string {
	ei, errDS := hex.DecodeString(eis)
	if errDS != nil {
		fmt.Println(errDS)
		return ""
	}
	return fmt.Sprintf("%x", mult(&privKey.PublicKey, ei, b))
}

func registerCallbacks() {
	js.Global().Set("generateKeys", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return generateKeysJS(args[0].Int())
	}))
	js.Global().Set("encrypt", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return encryptJS(args[0].Int())
	}))
	js.Global().Set("decrypt", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return decryptJS(args[0].String())
	}))
	js.Global().Set("add", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return addJS(args[0].String(), args[1].String())
	}))
	js.Global().Set("mult", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		return multJS(args[0].String(), args[1].Int())
	}))
}

func main() {
    c := make(chan struct{}, 0)

	// register functions
	registerCallbacks()
    println("WASM Go Initialized")

    <-c
}
