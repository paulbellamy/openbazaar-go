package zcash

import (
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
)

type FakeKeystore struct {
	put                 func(hash160 []byte, keyPath wallet.KeyPath) error
	importKey           func(scriptAddress []byte, key *btcec.PrivateKey) error
	markKeyAsUsed       func(scriptAddress []byte) error
	getLastKeyIndex     func(purpose wallet.KeyPurpose) (int, bool, error)
	getPathForKey       func(scriptAddress []byte) (wallet.KeyPath, error)
	getKey              func(scriptAddress []byte) (*btcec.PrivateKey, error)
	getImported         func() ([]*btcec.PrivateKey, error)
	getUnused           func(purpose wallet.KeyPurpose) ([]int, error)
	getAll              func() ([]wallet.KeyPath, error)
	getLookaheadWindows func() map[wallet.KeyPurpose]int
}

// Put a bip32 key to the database
func (f *FakeKeystore) Put(hash160 []byte, keyPath wallet.KeyPath) error {
	if f.put == nil {
		panic("not implemented")
	}
	return f.put(hash160, keyPath)
}

// Import a loose private key not part of the keychain
func (f *FakeKeystore) ImportKey(scriptAddress []byte, key *btcec.PrivateKey) error {
	if f.importKey == nil {
		panic("not implemented")
	}
	return f.importKey(scriptAddress, key)
}

// Mark the script as used
func (f *FakeKeystore) MarkKeyAsUsed(scriptAddress []byte) error {
	if f.markKeyAsUsed == nil {
		panic("not implemented")
	}
	return f.MarkKeyAsUsed(scriptAddress)
}

// Fetch the last index for the given key purpose
// The bool should state whether the key has been used or not
func (f *FakeKeystore) GetLastKeyIndex(purpose wallet.KeyPurpose) (int, bool, error) {
	if f.getLastKeyIndex == nil {
		panic("not implemented")
	}
	return f.getLastKeyIndex(purpose)
}

// Returns the first unused path for the given purpose
func (f *FakeKeystore) GetPathForKey(scriptAddress []byte) (wallet.KeyPath, error) {
	if f.getPathForKey == nil {
		panic("not implemented")
	}
	return f.GetPathForKey(scriptAddress)
}

// Returns an imported private key given a script address
func (f *FakeKeystore) GetKey(scriptAddress []byte) (*btcec.PrivateKey, error) {
	if f.getKey == nil {
		panic("not implemented")
	}
	return f.getKey(scriptAddress)
}

// Returns all imported keys
func (f *FakeKeystore) GetImported() ([]*btcec.PrivateKey, error) {
	if f.getImported == nil {
		panic("not implemented")
	}
	return f.getImported()
}

// Get a list of unused key indexes for the given purpose
func (f *FakeKeystore) GetUnused(purpose wallet.KeyPurpose) ([]int, error) {
	if f.getUnused == nil {
		panic("not implemented")
	}
	return f.getUnused(purpose)
}

// Fetch all key paths
func (f *FakeKeystore) GetAll() ([]wallet.KeyPath, error) {
	if f.getAll == nil {
		panic("not implemented")
	}
	return f.getAll()
}

// Get the number of unused keys following the last used key
// for each key purpose.
func (f *FakeKeystore) GetLookaheadWindows() map[wallet.KeyPurpose]int {
	if f.getLookaheadWindows == nil {
		panic("not implemented")
	}
	return f.getLookaheadWindows()
}
