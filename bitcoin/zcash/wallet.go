package zcash

import (
	"time"

	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcashd"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btc "github.com/btcsuite/btcutil"
	hd "github.com/btcsuite/btcutil/hdkeychain"
)

type Wallet struct {
	params *chaincfg.Params
}

func NewWallet(mnemonic string, params *chaincfg.Params, repoPath string, trustedPeer string, useTor bool, torControlPort int) (*Wallet, error) {
	return &Wallet{
		params: params,
	}, nil
}

// Start the wallet
func (w *Wallet) Start() {
	panic("not implemented")
}

// Return the network parameters
func (w *Wallet) Params() *chaincfg.Params {
	return w.params
}

// Returns the type of crytocurrency this wallet implements
func (w *Wallet) CurrencyCode() string {
	if w.params.Name != chaincfg.MainNetParams.Name {
		return "tzec"
	}
	return "zec"
}

// Check if this amount is considered dust
func (w *Wallet) IsDust(amount int64) bool {
	panic("not implemented")
}

// Get the master private key
func (w *Wallet) MasterPrivateKey() *hd.ExtendedKey {
	panic("not implemented")
}

// Get the master public key
func (w *Wallet) MasterPublicKey() *hd.ExtendedKey {
	panic("not implemented")
}

// Get the current address for the given purpose
func (w *Wallet) CurrentAddress(purpose wallet.KeyPurpose) btc.Address {
	panic("not implemented")
}

// Returns a fresh address that has never been returned by this function
func (w *Wallet) NewAddress(purpose wallet.KeyPurpose) btc.Address {
	panic("not implemented")
}

// Parse the address string and return an address interface
func (w *Wallet) DecodeAddress(addr string) (btc.Address, error) {
	panic("not implemented")
}

// Turn the given output script into an address
// TODO: Use multiwallet for this
func (w *Wallet) ScriptToAddress(script []byte) (btc.Address, error) {
	return zcashd.ExtractPkScriptAddrs(script, w.params)
}

// Turn the given address into an output script
func (w *Wallet) AddressToScript(addr btc.Address) ([]byte, error) {
	panic("not implemented")
}

// Returns if the wallet has the key for the given address
func (w *Wallet) HasKey(addr btc.Address) bool {
	panic("not implemented")
}

// Get the confirmed and unconfirmed balances
func (w *Wallet) Balance() (confirmed, unconfirmed int64) {
	panic("not implemented")
}

// Returns a list of transactions for this wallet
func (w *Wallet) Transactions() ([]wallet.Txn, error) {
	panic("not implemented")
}

// Get info on a specific transaction
func (w *Wallet) GetTransaction(txid chainhash.Hash) (wallet.Txn, error) {
	panic("not implemented")
}

// Get the height and best hash of the blockchain
func (w *Wallet) ChainTip() (uint32, chainhash.Hash) {
	panic("not implemented")
}

// Get the current fee per byte
func (w *Wallet) GetFeePerByte(feeLevel wallet.FeeLevel) uint64 {
	panic("not implemented")
}

// Send bitcoins to an external wallet
func (w *Wallet) Spend(amount int64, addr btc.Address, feeLevel wallet.FeeLevel) (*chainhash.Hash, error) {
	panic("not implemented")
}

// Bump the fee for the given transaction
func (w *Wallet) BumpFee(txid chainhash.Hash) (*chainhash.Hash, error) {
	panic("not implemented")
}

// Calculates the estimated size of the transaction and returns the total fee for the given feePerByte
func (w *Wallet) EstimateFee(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, feePerByte uint64) uint64 {
	panic("not implemented")
}

// Build a spend transaction for the amount and return the transaction fee
func (w *Wallet) EstimateSpendFee(amount int64, feeLevel wallet.FeeLevel) (uint64, error) {
	panic("not implemented")
}

// Build and broadcast a transaction that sweeps all coins from an address. If it is a p2sh multisig, the redeemScript must be included
func (w *Wallet) SweepAddress(utxos []wallet.Utxo, address *btc.Address, key *hd.ExtendedKey, redeemScript *[]byte, feeLevel wallet.FeeLevel) (*chainhash.Hash, error) {
	panic("not implemented")
}

// Create a signature for a multisig transaction
func (w *Wallet) CreateMultisigSignature(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, key *hd.ExtendedKey, redeemScript []byte, feePerByte uint64) ([]wallet.Signature, error) {
	panic("not implemented")
}

// Combine signatures and optionally broadcast
func (w *Wallet) Multisign(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, sigs1, sigs2 []wallet.Signature, redeemScript []byte, feePerByte uint64, broadcast bool) ([]byte, error) {
	panic("not implemented")
}

// Generate a multisig script from public keys. If a timeout is included the returned script should be a timelocked escrow which releases using the timeoutKey.
func (w *Wallet) GenerateMultisigScript(keys []hd.ExtendedKey, threshold int, timeout time.Duration, timeoutKey *hd.ExtendedKey) (addr btc.Address, redeemScript []byte, err error) {
	panic("not implemented")
}

// Add a script to the wallet and get notifications back when coins are received or spent from it
func (w *Wallet) AddWatchedScript(script []byte) error {
	panic("not implemented")
}

// Add a callback for incoming transactions
func (w *Wallet) AddTransactionListener(func(wallet.TransactionCallback)) {
	panic("not implemented")
}

// Use this to re-download merkle blocks in case of missed transactions
func (w *Wallet) ReSyncBlockchain(fromTime time.Time) {
	panic("not implemented")
}

// Return the number of confirmations and the height for a transaction
func (w *Wallet) GetConfirmations(txid chainhash.Hash) (confirms, atHeight uint32, err error) {
	panic("not implemented")
}

// Cleanly disconnect from the wallet
func (w *Wallet) Close() {
	panic("not implemented")
}