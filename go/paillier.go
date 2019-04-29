package main

import (
	"fmt"
	"crypto/rand"
	"math/big"

	paillier "github.com/Roasbeef/go-go-gadget-paillier"
)

func generateKeys(bits int) (*paillier.PrivateKey, error){
	// Generate a 128-bit private key.
	privKey, err := paillier.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generateKeys(%d): %v", err)
	}

	return privKey, nil
}

func encrypt(pk *paillier.PublicKey, i int) ([]byte, error) {
	bi := new(big.Int).SetInt64(int64(i))
	ei, err := paillier.Encrypt(pk, bi.Bytes())
	if err != nil {
		return nil, fmt.Errorf("encrypt(%d): %v", i, err)
	}

	return ei, nil
}

func decrypt(sk *paillier.PrivateKey, ei []byte) (int, error) {
	dib, err := paillier.Decrypt(sk, ei)
	if err != nil {
		return 0, fmt.Errorf("decrypt(%x): %v", ei, err)
	}
	di := new(big.Int).SetBytes(dib)
	if !di.IsInt64() {
		return 0, fmt.Errorf("decrypt(%x): %s is not a int64", di.String())
	}
	is := int(di.Int64())

	return is, nil
}

func add(pk *paillier.PublicKey, a, b []byte) []byte {
	return paillier.AddCipher(pk, a, b)
}

func mult(pk *paillier.PublicKey, ei []byte, b int) []byte {
	return paillier.Mul(pk, ei, new(big.Int).SetInt64(int64(b)).Bytes())
}