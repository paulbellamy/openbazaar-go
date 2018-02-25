package zcash

import (
	"fmt"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcashd"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btc "github.com/btcsuite/btcutil"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/op/go-logging"
	b39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/net/proxy"
)

var log = logging.MustGetLogger("zcash")

type Wallet struct {
	Config
	keyManager       *keys.KeyManager
	masterPrivateKey *hd.ExtendedKey
	masterPublicKey  *hd.ExtendedKey
	insight          InsightClient
	txStore          TxStore
	stopChan         chan struct{}
}

type Config struct {
	Mnemonic    string
	Params      *chaincfg.Params
	RepoPath    string
	TrustedPeer string
	DB          wallet.Datastore
	Proxy       proxy.Dialer
}

// Stubbable for testing
var newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
	return client.NewInsightClient(url, proxyDialer)
}

type InsightClient interface {
	GetTransactions(addrs []btc.Address) ([]client.Transaction, error)
	GetRawTransaction(txid string) ([]byte, error)
	TransactionNotify() <-chan client.Transaction
}

func NewWallet(config Config) (*Wallet, error) {
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	mPubKey, _ := mPrivKey.Neuter()
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		return nil, err
	}
	insight, err := newInsightClient(fmt.Sprintf("https://%s/api", config.TrustedPeer), config.Proxy)
	if err != nil {
		return nil, err
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		return nil, err
	}

	w := &Wallet{
		Config:           config,
		keyManager:       keyManager,
		masterPrivateKey: mPrivKey,
		masterPublicKey:  mPubKey,
		insight:          insight,
		txStore:          txStore,
		stopChan:         make(chan struct{}),
	}

	return w, nil
}

func (w *Wallet) getAddresses() (addrs []btc.Address) {
	for _, k := range w.keyManager.GetKeys() {
		addrs = append(addrs, keyToAddress(k, w.Config.Params))
	}
	return addrs
}

func (w *Wallet) ingest(txn client.Transaction) error {
	raw, err := w.insight.GetRawTransaction(txn.Txid)
	if err != nil {
		return err
	}
	return w.txStore.Ingest(txn, raw)
}

// Start the wallet
// Load initial transactions, and watch for more.
// TODO: check if there is a race between loading and watching (if a new txn
// appears after load, before watch).
func (w *Wallet) Start() {
	w.loadInitialTransactions()
	go w.watchTransactions()
}

func (w *Wallet) loadInitialTransactions() {
	txns, err := w.insight.GetTransactions(w.getAddresses())
	if err != nil {
		log.Error(err)
		return
	}
	for _, txn := range txns {
		if err := w.ingest(txn); err != nil {
			log.Error(err)
			return
		}
	}
}

func (w *Wallet) watchTransactions() {
	for {
		select {
		case <-w.stopChan:
			return
		case txn, ok := <-w.insight.TransactionNotify():
			if !ok {
				return
			}
			if err := w.ingest(txn); err != nil {
				log.Errorf("error fetching transaction %v: %v", txn.Txid, err)
			} else {
				log.Debugf("fetched transaction %v", txn.Txid)
			}
		}
	}
}

// Return the network parameters
func (w *Wallet) Params() *chaincfg.Params {
	return w.Config.Params
}

// Returns the type of crytocurrency this wallet implements
func (w *Wallet) CurrencyCode() string {
	if w.Config.Params.Name != chaincfg.MainNetParams.Name {
		return "tzec"
	}
	return "zec"
}

// Check if this amount is considered dust
// TODO: Follow up https://github.com/zcash/zcash/issues/2133
func (w *Wallet) IsDust(amount int64) bool {
	return txrules.IsDustAmount(btc.Amount(amount), 25, txrules.DefaultRelayFeePerKb)
}

// Get the master private key
func (w *Wallet) MasterPrivateKey() *hd.ExtendedKey {
	return w.masterPrivateKey
}

// Get the master public key
func (w *Wallet) MasterPublicKey() *hd.ExtendedKey {
	return w.masterPublicKey
}

// Get the current address for the given purpose
// TODO: Handle these errors
// TODO: Use multiwallet for this
func (w *Wallet) CurrentAddress(purpose wallet.KeyPurpose) btc.Address {
	key, _ := w.keyManager.GetCurrentKey(purpose)
	return keyToAddress(key, w.Config.Params)
}

// Returns a fresh address that has never been returned by this function
func (w *Wallet) NewAddress(purpose wallet.KeyPurpose) btc.Address {
	key, _ := w.keyManager.GetFreshKey(purpose)
	addr := keyToAddress(key, w.Config.Params)
	w.DB.Keys().MarkKeyAsUsed(addr.ScriptAddress())
	return addr
}

func keyToAddress(key *hd.ExtendedKey, params *chaincfg.Params) btc.Address {
	pubkey, _ := key.ECPubKey()
	addr, _ := zcashd.NewAddressPubKeyHash(btc.Hash160(pubkey.SerializeUncompressed()), params)
	return addr
}

// Parse the address string and return an address interface
// TODO: Use multiwallet for this, maybe
func (w *Wallet) DecodeAddress(addr string) (btc.Address, error) {
	return zcashd.DecodeAddress(addr, w.Config.Params)
}

// Turn the given output script into an address
// TODO: Use multiwallet for this
func (w *Wallet) ScriptToAddress(script []byte) (btc.Address, error) {
	return zcashd.ExtractPkScriptAddrs(script, w.Config.Params)
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
// TODO: Handle these errors
// TODO: Track and figure out how the utxos/stxos get populated in the real app
func (w *Wallet) Balance() (confirmed, unconfirmed int64) {
	utxos, _ := w.DB.Utxos().GetAll()
	stxos, _ := w.DB.Stxos().GetAll()
	for _, utxo := range utxos {
		if !utxo.WatchOnly {
			if utxo.AtHeight > 0 {
				confirmed += utxo.Value
			} else {
				if w.checkIfStxoIsConfirmed(utxo, stxos) {
					confirmed += utxo.Value
				} else {
					unconfirmed += utxo.Value
				}
			}
		}
	}
	return confirmed, unconfirmed
}

func (w *Wallet) checkIfStxoIsConfirmed(utxo wallet.Utxo, stxos []wallet.Stxo) bool {
	for _, stxo := range stxos {
		if !stxo.Utxo.WatchOnly {
			if stxo.SpendTxid.IsEqual(&utxo.Op.Hash) {
				if stxo.SpendHeight > 0 {
					println("utxo", fmt.Sprint(utxo), "matched spent stxo:", fmt.Sprint(stxo), "utxo confirmed")
					return true
				} else {
					println("utxo", fmt.Sprint(utxo), "matched unspent stxo:", fmt.Sprint(stxo), "recursing")
					return w.checkIfStxoIsConfirmed(stxo.Utxo, stxos)
				}
			} else if stxo.Utxo.IsEqual(&utxo) {
				if stxo.Utxo.AtHeight > 0 {
					println("stxo.Utxo.AtHeight:", stxo.Utxo.AtHeight, "utxo confirmed")
					return true
				} else {
					println("stxo.Utxo.AtHeight:", stxo.Utxo.AtHeight, "utxo unconfirmed")
					return false
				}
			}
		}
	}
	return false
}

// Returns a list of transactions for this wallet
func (w *Wallet) Transactions() ([]wallet.Txn, error) {
	return w.DB.Txns().GetAll(false)
}

// Get info on a specific transaction
func (w *Wallet) GetTransaction(txid chainhash.Hash) (wallet.Txn, error) {
	panic("not implemented")
}

// Get the height and best hash of the blockchain
// TODO: Implement this
func (w *Wallet) ChainTip() (uint32, chainhash.Hash) {
	var ch chainhash.Hash
	return 0, ch
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
// TODO: Implement this
func (w *Wallet) AddTransactionListener(func(wallet.TransactionCallback)) {
}

// Use this to re-download merkle blocks in case of missed transactions
// TODO: Implement this
func (w *Wallet) ReSyncBlockchain(fromTime time.Time) {
}

// Return the number of confirmations and the height for a transaction
func (w *Wallet) GetConfirmations(txid chainhash.Hash) (confirms, atHeight uint32, err error) {
	panic("not implemented")
}

// Cleanly disconnect from the wallet
func (w *Wallet) Close() {
	close(w.stopChan)
}
