package zcash

import (
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
)

type FakeDatastore struct {
	utxos          wallet.Utxos
	stxos          wallet.Stxos
	txns           wallet.Txns
	keys           wallet.Keys
	watchedScripts wallet.WatchedScripts
}

func (f *FakeDatastore) Utxos() wallet.Utxos                   { return f.utxos }
func (f *FakeDatastore) Stxos() wallet.Stxos                   { return f.stxos }
func (f *FakeDatastore) Txns() wallet.Txns                     { return f.txns }
func (f *FakeDatastore) Keys() wallet.Keys                     { return f.keys }
func (f *FakeDatastore) WatchedScripts() wallet.WatchedScripts { return f.watchedScripts }

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
	return f.markKeyAsUsed(scriptAddress)
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

type FakeUtxos struct {
	// Put a utxo to the database
	put func(utxo wallet.Utxo) error

	// Fetch all utxos from the db
	getAll func() ([]wallet.Utxo, error)

	// Make a utxo unspendable
	setWatchOnly func(utxo wallet.Utxo) error

	// Delete a utxo from the db
	delete func(utxo wallet.Utxo) error
}

// Put a utxo to the database
func (f *FakeUtxos) Put(utxo wallet.Utxo) error {
	if f.put == nil {
		panic("not implemented")
	}
	return f.put(utxo)
}

// Fetch all utxos from the db
func (f *FakeUtxos) GetAll() ([]wallet.Utxo, error) {
	if f.getAll == nil {
		panic("not implemented")
	}
	return f.getAll()
}

// Make a utxo unspendable
func (f *FakeUtxos) SetWatchOnly(utxo wallet.Utxo) error {
	if f.setWatchOnly == nil {
		panic("not implemented")
	}
	return f.setWatchOnly(utxo)
}

// Delete a utxo from the db
func (f *FakeUtxos) Delete(utxo wallet.Utxo) error {
	if f.delete == nil {
		panic("not implemented")
	}
	return f.delete(utxo)
}

type FakeStxos struct {
	// Put a stxo to the database
	put func(stxo wallet.Stxo) error

	// Fetch all stxos from the db
	getAll func() ([]wallet.Stxo, error)

	// Delete a stxo from the db
	delete func(stxo wallet.Stxo) error
}

// Put a stxo to the database
func (f *FakeStxos) Put(stxo wallet.Stxo) error {
	if f.put == nil {
		panic("not implemented")
	}
	return f.put(stxo)
}

// Fetch all stxos from the db
func (f *FakeStxos) GetAll() ([]wallet.Stxo, error) {
	if f.getAll == nil {
		panic("not implemented")
	}
	return f.getAll()
}

// Delete a stxo from the db
func (f *FakeStxos) Delete(stxo wallet.Stxo) error {
	if f.delete == nil {
		panic("not implemented")
	}
	return f.delete(stxo)
}
