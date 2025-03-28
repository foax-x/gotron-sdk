//go:build !windows
// +build !windows

package keystore

import (
	"github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/foax-x/gotron-sdk/pkg/address"
)

func RecoverPubkey(hash []byte, signature []byte) (address.Address, error) {

	if signature[64] >= 27 {
		signature[64] -= 27
	}

	sigPublicKey, _, err := secp256k1.RecoverCompact(signature, hash)
	if err != nil {
		return nil, err
	}
	pubKey, err := UnmarshalPublic(sigPublicKey.X.Bytes())
	if err != nil {
		return nil, err
	}

	addr := address.PubkeyToAddress(*pubKey)
	return addr, nil
}
