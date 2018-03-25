package zcash

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcashd"
	"github.com/OpenBazaar/spvwallet"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btc "github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/coinset"
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
	GetLatestBlock() (*client.Block, error)
	GetTransactions(addrs []btc.Address) ([]client.Transaction, error)
	GetRawTransaction(txid string) ([]byte, error)
	TransactionNotify() <-chan client.Transaction
	Broadcast(tx []byte) (string, error)
}

func NewWallet(config Config) (*Wallet, error) {
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	mPubKey, _ := mPrivKey.Neuter()
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash, keyToAddress)
	if err != nil {
		return nil, fmt.Errorf("error initializing key manager: %v", err)
	}
	insight, err := newInsightClient(fmt.Sprintf("https://%s/api", config.TrustedPeer), config.Proxy)
	if err != nil {
		return nil, fmt.Errorf("error initializing insight client: %v", err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		return nil, fmt.Errorf("error initializing txstore: %v", err)
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

// Start the wallet
// Load initial transactions, and watch for more.
// TODO: check if there is a race between loading and watching (if a new txn
// appears after load, before watch).
func (w *Wallet) Start() {
	w.loadInitialTransactions()
	go w.watchTransactions()
}

func (w *Wallet) onTxn(txn client.Transaction) error {
	raw, err := w.insight.GetRawTransaction(txn.Txid)
	if err != nil {
		return err
	}
	return w.txStore.Ingest(txn, raw)
}

func (w *Wallet) loadInitialTransactions() {
	addrs, err := keysToAddresses(w.Params(), w.keyManager.GetKeys())
	if err != nil {
		log.Error(err)
		return
	}
	txns, err := w.insight.GetTransactions(addrs)
	if err != nil {
		log.Error(err)
		return
	}
	for _, txn := range txns {
		if err := w.onTxn(txn); err != nil {
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
			if err := w.onTxn(txn); err != nil {
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
	if w.Params().Name != chaincfg.MainNetParams.Name {
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
	addr, _ := keyToAddress(key, w.Params())
	return addr
}

// Returns a fresh address that has never been returned by this function
func (w *Wallet) NewAddress(purpose wallet.KeyPurpose) btc.Address {
	key, _ := w.keyManager.GetFreshKey(purpose)
	addr, _ := keyToAddress(key, w.Params())
	w.DB.Keys().MarkKeyAsUsed(addr.ScriptAddress())
	return addr
}

func keysToAddresses(params *chaincfg.Params, keys []*hd.ExtendedKey) (addrs []btc.Address, err error) {
	for _, k := range keys {
		addr, err := keyToAddress(k, params)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

func keyToAddress(key *hd.ExtendedKey, params *chaincfg.Params) (btc.Address, error) {
	pubkey, err := key.ECPubKey()
	if err != nil {
		return nil, err
	}
	return zcashd.NewAddressPubKeyHash(btc.Hash160(pubkey.SerializeUncompressed()), params)
}

// Parse the address string and return an address interface
// TODO: Use multiwallet for this, maybe
func (w *Wallet) DecodeAddress(addr string) (btc.Address, error) {
	return zcashd.DecodeAddress(addr, w.Params())
}

// Turn the given output script into an address
// TODO: Use multiwallet for this
func (w *Wallet) ScriptToAddress(script []byte) (btc.Address, error) {
	return zcashd.ExtractPkScriptAddrs(script, w.Params())
}

// Turn the given address into an output script
func (w *Wallet) AddressToScript(addr btc.Address) ([]byte, error) {
	return zcashd.PayToAddrScript(addr)
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
	return w.DB.Txns().Get(txid)
}

// Get the height and best hash of the blockchain
// TODO: We should fetch all blocks and watch for changes here instead of being
// so dependent on the insight api
func (w *Wallet) ChainTip() (uint32, chainhash.Hash) {
	block, err := w.insight.GetLatestBlock()
	if err != nil {
		log.Errorf("error fetching latest block: %v", err)
		return 0, chainhash.Hash{}
	}
	hash, _ := chainhash.NewHashFromStr(block.Hash)
	return uint32(block.Height), *hash
}

// Get the current fee per byte
func (w *Wallet) GetFeePerByte(feeLevel wallet.FeeLevel) uint64 {
	panic("not implemented")
}

// Send bitcoins to an external wallet
func (w *Wallet) Spend(amount int64, addr btc.Address, feeLevel wallet.FeeLevel) (*chainhash.Hash, error) {
	txn, err := w.buildTxn(amount, addr, feeLevel)
	if err != nil {
		return nil, err
	}
	hash, err := w.insight.Broadcast(txn)
	if err != nil {
		return nil, err
	}
	return chainhash.NewHashFromStr(hash)
}

func (w *Wallet) buildTxn(amount int64, addr btc.Address, feeLevel wallet.FeeLevel) ([]byte, error) {
	// Check for dust
	script, err := w.AddressToScript(addr)
	if err != nil {
		return nil, err
	}
	if txrules.IsDustAmount(btc.Amount(amount), len(script), txrules.DefaultRelayFeePerKb) {
		return nil, wallet.ErrorDustAmount
	}

	inputs, total, err := w.buildTxnInputs(amount, feeLevel)
	if err != nil {
		return nil, err
	}
	outputs, err := w.buildTxnOutputs(amount, total-amount, script)
	if err != nil {
		return nil, err
	}
	txn := &Transaction{Inputs: inputs, Outputs: outputs}
	consensusBranchId := uint32(0) // TODO: Figure this out for overwinter w.CurrentEpochBranchId(chainActive.Height() + 1, w.Params().GetConsensus())
	txn, err = w.Sign(txn, SigHashAll, consensusBranchId)
	if err != nil {
		return nil, fmt.Errorf("error signing txn: %v", err)
	}
	return txn.MarshalBinary()
}

func (w *Wallet) buildTxnInputs(amount int64, feeLevel wallet.FeeLevel) ([]Input, int64, error) {
	//feePerKB := int64(w.GetFeePerByte(feeLevel)) * 1000
	target := amount // TODO: + Fees
	coinMap, err := w.gatherCoins()
	if err != nil {
		return nil, 0, err
	}
	coins := make([]coinset.Coin, 0, len(coinMap))
	for k := range coinMap {
		coins = append(coins, k)
	}
	coinSelector := coinset.MaxValueAgeCoinSelector{MaxInputs: 10000, MinChangeAmount: btc.Amount(0)}
	selected, err := coinSelector.CoinSelect(btc.Amount(target), coins)
	if err != nil {
		return nil, 0, wallet.ErrorInsuffientFunds
	}
	var inputs []Input
	var total btc.Amount
	for i, c := range selected.Coins() {
		input := Input{
			Txid: c.Hash().String(),
			Vout: int(c.Index()),
			N:    i,
			ScriptSig: Script{
				// Script where we received this utxo. During signing it gets replaced
				// with the signature.
				Hex: hex.EncodeToString(c.PkScript()),
			},
		}
		inputs = append(inputs, input)
		total += c.Value()
	}
	return inputs, int64(total), nil
}

func (w *Wallet) gatherCoins() (map[coinset.Coin]*hd.ExtendedKey, error) {
	height, _ := w.ChainTip()
	utxos, err := w.DB.Utxos().GetAll()
	if err != nil {
		return nil, err
	}
	m := make(map[coinset.Coin]*hd.ExtendedKey)
	for _, u := range utxos {
		if u.WatchOnly {
			continue
		}
		var confirmations int32
		if u.AtHeight > 0 {
			confirmations = int32(height) - u.AtHeight
		}
		c := spvwallet.NewCoin(u.Op.Hash.CloneBytes(), u.Op.Index, btc.Amount(u.Value), int64(confirmations), u.ScriptPubkey)
		addr, err := w.ScriptToAddress(u.ScriptPubkey)
		if err != nil {
			continue
		}
		key, err := w.keyManager.GetKeyForScript(addr.ScriptAddress())
		if err != nil {
			continue
		}
		m[c] = key
	}
	return m, nil
}

// TODO: Check this against the spvwallet library
// TODO: Handle and add fees into this
func (w *Wallet) buildTxnOutputs(amount, changeAmount int64, outScript []byte) ([]client.Output, error) {
	changeScript, err := w.AddressToScript(w.CurrentAddress(wallet.INTERNAL))
	if err != nil {
		return nil, err
	}
	outputs := []client.Output{
		client.Output{
			Value: float64(amount) / 1e8, // TODO: Stop using floats! Insight api is rife with this crap
			N:     0,
			ScriptPubKey: client.OutScript{
				Script: client.Script{Hex: hex.EncodeToString(outScript)},
			},
		},
		client.Output{
			Value: float64(changeAmount) / 1e8, // TODO: Stop using floats! Insight api is rife with this crap
			N:     1,
			ScriptPubKey: client.OutScript{
				Script: client.Script{Hex: hex.EncodeToString(changeScript)},
			},
		},
	}
	return outputs, nil
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
	txn, err := w.DB.Txns().Get(txid)
	if err != nil || txn.Height == 0 {
		return 0, 0, err
	}
	chainTip, _ := w.ChainTip()
	return chainTip - uint32(txn.Height) + 1, uint32(txn.Height), nil
}

// Cleanly disconnect from the wallet
func (w *Wallet) Close() {
	close(w.stopChan)
}
