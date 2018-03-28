package zcash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	"github.com/OpenBazaar/spvwallet"
	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btc "github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/coinset"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/btcsuite/btcutil/txsort"
	"github.com/btcsuite/btcwallet/wallet/txrules"
	"github.com/op/go-logging"
	b39 "github.com/tyler-smith/go-bip39"
	"golang.org/x/net/proxy"
)

var log = logging.MustGetLogger("zcash")

type Wallet struct {
	Config
	keyManager             *keys.KeyManager
	masterPrivateKey       *hd.ExtendedKey
	masterPublicKey        *hd.ExtendedKey
	listeners              []func(wallet.TransactionCallback)
	insight                InsightClient
	txStore                *TxStore
	initChan               chan struct{}
	addrSubscriptions      map[btc.Address]struct{}
	addrSubscriptionsMutex sync.Mutex
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
	EstimateFee(nbBlocks int) (int, error)
	ListenAddress(addr btc.Address)
	Close()
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
		Config:            config,
		keyManager:        keyManager,
		masterPrivateKey:  mPrivKey,
		masterPublicKey:   mPubKey,
		insight:           insight,
		txStore:           txStore,
		initChan:          make(chan struct{}),
		addrSubscriptions: make(map[btc.Address]struct{}),
	}

	return w, nil
}

// TestNetworkEnabled indicates if the current network being used is Test Network
func (w *Wallet) TestNetworkEnabled() bool {
	return w.Params().Name == chaincfg.TestNet3Params.Name
}

// RegressionNetworkEnabled indicates if the current network being used is Regression Network
func (w *Wallet) RegressionNetworkEnabled() bool {
	return w.Params().Name == chaincfg.RegressionNetParams.Name
}

// MainNetworkEnabled indicates if the current network being used is the live Network
func (w *Wallet) MainNetworkEnabled() bool {
	return w.Params().Name == chaincfg.MainNetParams.Name
}

func (w *Wallet) Start() {
	w.subscribeToAllAddresses()
	w.loadInitialTransactions()
	go w.watchTransactions()
	close(w.initChan)
}

func (w *Wallet) onTxn(txn client.Transaction) error {
	raw, err := w.insight.GetRawTransaction(txn.Txid)
	if err != nil {
		return err
	}
	msgTx := &wire.MsgTx{
		Version:  int32(txn.Version),
		TxIn:     make([]*wire.TxIn, len(txn.Inputs)),
		TxOut:    make([]*wire.TxOut, len(txn.Outputs)),
		LockTime: uint32(txn.Time),
	}
	for i, input := range txn.Inputs {
		hash, err := chainhash.NewHashFromStr(input.Txid)
		if err != nil {
			return err
		}
		sigScript, err := hex.DecodeString(input.ScriptSig.Hex)
		if err != nil {
			return err
		}
		msgTx.TxIn[i] = &wire.TxIn{
			PreviousOutPoint: wire.OutPoint{
				Hash:  *hash,
				Index: uint32(input.Vout),
			},
			SignatureScript: sigScript,
			Sequence:        uint32(input.Sequence), // TODO: Is this sequence right?
		}
	}
	for i, output := range txn.Outputs {
		value, err := output.ValueSat()
		if err != nil {
			return err
		}
		pkScript, err := hex.DecodeString(output.ScriptPubKey.Hex)
		if err != nil {
			return err
		}
		msgTx.TxOut[i] = &wire.TxOut{
			Value:    value,
			PkScript: pkScript,
		}
	}
	_, err = w.txStore.Ingest(msgTx, raw, int32(txn.BlockHeight))
	return err
}

func (w *Wallet) subscribeToAllAddresses() {
	keys := w.keyManager.GetKeys()
	for _, k := range keys {
		if addr, err := keyToAddress(k, w.Params()); err == nil {
			w.addWatchedAddr(addr)
		}
	}
	scripts, _ := w.DB.WatchedScripts().GetAll()
	for _, script := range scripts {
		if addr, err := w.ScriptToAddress(script); err == nil {
			w.addWatchedAddr(addr)
		}
	}
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
	if w.MainNetworkEnabled() {
		return "zec"
	}
	return "tzec"
}

// Check if this amount is considered dust
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
	return NewAddressPubKeyHash(btc.Hash160(pubkey.SerializeUncompressed()), params)
}

// Parse the address string and return an address interface
func (w *Wallet) DecodeAddress(addr string) (btc.Address, error) {
	return DecodeAddress(addr, w.Params())
}

// Turn the given output script into an address
func (w *Wallet) ScriptToAddress(script []byte) (btc.Address, error) {
	return ExtractPkScriptAddrs(script, w.Params())
}

// Turn the given address into an output script
func (w *Wallet) AddressToScript(addr btc.Address) ([]byte, error) {
	return PayToAddrScript(addr)
}

// Returns if the wallet has the key for the given address
func (w *Wallet) HasKey(addr btc.Address) bool {
	<-w.initChan
	_, err := w.hdKeyForAddress(addr)
	return err == nil
}

// Get the confirmed and unconfirmed balances
// TODO: Handle this error
// TODO: Maybe we could just use insight api for this
func (w *Wallet) Balance() (confirmed, unconfirmed int64) {
	<-w.initChan
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

func (w *Wallet) Transactions() ([]wallet.Txn, error) {
	<-w.initChan
	return w.DB.Txns().GetAll(false)
}

// Get info on a specific transaction
func (w *Wallet) GetTransaction(txid chainhash.Hash) (wallet.Txn, error) {
	<-w.initChan
	return w.DB.Txns().Get(txid)
}

// Get the height and best hash of the blockchain
// TODO: We should fetch all blocks and watch for changes here instead of being
// so dependent on the insight api
func (w *Wallet) ChainTip() (uint32, chainhash.Hash) {
	<-w.initChan
	block, err := w.insight.GetLatestBlock()
	if err != nil {
		log.Errorf("error fetching latest block: %v", err)
		return 0, chainhash.Hash{}
	}
	hash, _ := chainhash.NewHashFromStr(block.Hash)
	return uint32(block.Height), *hash
}

func (w *Wallet) Spend(amount int64, addr btc.Address, feeLevel wallet.FeeLevel) (*chainhash.Hash, error) {
	<-w.initChan
	txn, err := w.buildTxn(amount, addr, feeLevel)
	if err != nil {
		return nil, err
	}
	return w.broadcastWireTx(txn)
}

func (w *Wallet) broadcastWireTx(tx *wire.MsgTx) (*chainhash.Hash, error) {
	// Serialize the transaction and convert to hex string.
	buf := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	if err := tx.Serialize(buf); err != nil {
		return nil, err
	}

	hash, err := w.insight.Broadcast(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return chainhash.NewHashFromStr(hash)
}

func (w *Wallet) buildTxn(amount int64, addr btc.Address, feeLevel wallet.FeeLevel) (*wire.MsgTx, error) {
	script, err := PayToAddrScript(addr)
	if err != nil {
		return nil, err
	}
	if txrules.IsDustAmount(btc.Amount(amount), len(script), txrules.DefaultRelayFeePerKb) {
		return nil, wallet.ErrorDustAmount
	}

	var additionalPrevScripts map[wire.OutPoint][]byte
	var additionalKeysByAddress map[string]*btc.WIF

	// Create input source
	coinMap, err := w.gatherCoins()
	if err != nil {
		return nil, err
	}
	coins := make([]coinset.Coin, 0, len(coinMap))
	for k := range coinMap {
		coins = append(coins, k)
	}
	inputSource := func(target btc.Amount) (total btc.Amount, inputs []*wire.TxIn, scripts [][]byte, err error) {
		coinSelector := coinset.MaxValueAgeCoinSelector{MaxInputs: 10000, MinChangeAmount: btc.Amount(0)}
		coins, err := coinSelector.CoinSelect(target, coins)
		if err != nil {
			return total, inputs, scripts, wallet.ErrorInsuffientFunds
		}
		additionalPrevScripts = make(map[wire.OutPoint][]byte)
		additionalKeysByAddress = make(map[string]*btc.WIF)
		for _, c := range coins.Coins() {
			total += c.Value()
			outpoint := wire.NewOutPoint(c.Hash(), c.Index())
			in := wire.NewTxIn(outpoint, []byte{}, [][]byte{})
			in.Sequence = 0 // Opt-in RBF so we can bump fees
			inputs = append(inputs, in)
			additionalPrevScripts[*outpoint] = c.PkScript()
			key := coinMap[c]
			addr, err := keyToAddress(key, w.Params())
			if err != nil {
				continue
			}
			privKey, err := key.ECPrivKey()
			if err != nil {
				continue
			}
			wif, _ := btc.NewWIF(privKey, w.Params(), true)
			additionalKeysByAddress[addr.EncodeAddress()] = wif
		}
		return total, inputs, scripts, nil
	}

	// Get the fee per kilobyte
	feePerKB := int64(w.GetFeePerByte(feeLevel)) * 1000

	// outputs
	out := wire.NewTxOut(amount, script)

	// Create change source
	changeSource := func() ([]byte, error) {
		addr := w.CurrentAddress(wallet.INTERNAL)
		script, err := PayToAddrScript(addr)
		if err != nil {
			return []byte{}, err
		}
		return script, nil
	}

	outputs := []*wire.TxOut{out}
	authoredTx, err := spvwallet.NewUnsignedTransaction(outputs, btc.Amount(feePerKB), inputSource, changeSource)
	if err != nil {
		return nil, err
	}

	// BIP 69 sorting
	txsort.InPlaceSort(authoredTx.Tx)

	// Sign tx
	signed, err := w.Sign(authoredTx.Tx, txscript.SigHashAll, additionalPrevScripts, additionalKeysByAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %v", err)
	}
	return signed, nil
}

func (w *Wallet) gatherCoins() (map[coinset.Coin]*hd.ExtendedKey, error) {
	<-w.initChan
	tipHeight, _ := w.ChainTip()
	m := make(map[coinset.Coin]*hd.ExtendedKey)
	utxos, err := w.DB.Utxos().GetAll()
	if err != nil {
		return m, err
	}
	for _, u := range utxos {
		/*
			// TODO: Calculate if spendable
			if !u.Spendable {
				continue
			}
		*/
		c := spvwallet.NewCoin(u.Op.Hash.CloneBytes(), u.Op.Index, btc.Amount(u.Value), int64(tipHeight)-int64(u.AtHeight), u.ScriptPubkey)

		addr, err := w.ScriptToAddress(u.ScriptPubkey)
		if err != nil {
			continue
		}
		hdKey, err := w.hdKeyForAddress(addr)
		if err != nil {
			continue
		}
		m[c] = hdKey
	}
	return m, nil
}

func (w *Wallet) BumpFee(txid chainhash.Hash) (*chainhash.Hash, error) {
	<-w.initChan
	tipHeight, _ := w.ChainTip()
	tx, err := w.DB.Txns().Get(txid)
	if err != nil {
		return nil, err
	}
	if tx.WatchOnly {
		return nil, fmt.Errorf("not found")
	}
	if tx.Height <= 0 || tx.Height > int32(tipHeight) {
		return nil, spvwallet.BumpFeeAlreadyConfirmedError
	}
	unspent, err := w.DB.Utxos().GetAll()
	if err != nil {
		return nil, err
	}
	for _, u := range unspent {
		if u.Op.Hash.String() == txid.String() {
			if u.AtHeight > 0 && u.AtHeight < int32(tipHeight) {
				return nil, spvwallet.BumpFeeAlreadyConfirmedError
			}
			addr, err := w.ScriptToAddress(u.ScriptPubkey)
			if err != nil {
				continue
			}
			hdKey, err := w.hdKeyForAddress(addr)
			if err != nil {
				continue
			}
			transactionID, err := w.SweepAddress([]wallet.Utxo{u}, nil, hdKey, nil, wallet.FEE_BUMP)
			if err != nil {
				return nil, err
			}
			return transactionID, nil

		}
	}
	return nil, spvwallet.BumpFeeNotFoundError
}

func (w *Wallet) hdKeyForAddress(addr btc.Address) (*hd.ExtendedKey, error) {
	privKey, err := w.keyManager.GetKeyForScript(addr.ScriptAddress())
	if err != nil {
		return nil, err
	}
	ecPrivKey, err := privKey.ECPrivKey()
	if err != nil {
		return nil, err
	}
	return hd.NewExtendedKey(
		w.Params().HDPrivateKeyID[:],
		ecPrivKey.Serialize(),
		make([]byte, 32),
		[]byte{0x00, 0x00, 0x00, 0x00},
		0,
		0,
		true,
	), nil
}

// Get the current fee per byte
func (w *Wallet) GetFeePerByte(feeLevel wallet.FeeLevel) uint64 {
	<-w.initChan
	defaultFee := uint64(50)
	var nBlocks int
	switch feeLevel {
	case wallet.PRIOIRTY:
		nBlocks = 1
	case wallet.NORMAL:
		nBlocks = 3
	case wallet.ECONOMIC:
		nBlocks = 6
	default:
		return defaultFee
	}
	feePerKb, err := w.insight.EstimateFee(nBlocks)
	if err != nil {
		return defaultFee
	}
	if feePerKb <= 0 {
		return defaultFee
	}
	fee := feePerKb / 1000
	return uint64(fee)
}

// Calculates the estimated size of the transaction and returns the total fee for the given feePerByte
func (w *Wallet) EstimateFee(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, feePerByte uint64) uint64 {
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, out := range outs {
		output := wire.NewTxOut(out.Value, out.ScriptPubKey)
		tx.TxOut = append(tx.TxOut, output)
	}
	estimatedSize := spvwallet.EstimateSerializeSize(len(ins), tx.TxOut, false, spvwallet.P2PKH)
	fee := estimatedSize * int(feePerByte)
	return uint64(fee)
}

// Build a spend transaction for the amount and return the transaction fee
func (w *Wallet) EstimateSpendFee(amount int64, feeLevel wallet.FeeLevel) (uint64, error) {
	<-w.initChan
	addr, err := DecodeAddress("t1VpYecBW4UudbGcy4ufh61eWxQCoFaUrPs", &chaincfg.MainNetParams)
	if err != nil {
		return 0, err
	}
	txn, err := w.buildTxn(amount, addr, feeLevel)
	if err != nil {
		return 0, err
	}
	var outval int64
	for _, output := range txn.TxOut {
		outval += output.Value
	}
	var inval int64
	utxos, err := w.DB.Utxos().GetAll()
	if err != nil {
		return 0, err
	}
	for _, input := range txn.TxIn {
		for _, utxo := range utxos {
			if outpointsEqual(utxo.Op, input.PreviousOutPoint) {
				inval += int64(utxo.Value * 100000000)
				break
			}
		}
	}
	if inval < outval {
		return 0, errors.New("Error building transaction: inputs less than outputs")
	}
	return uint64(inval - outval), err
}

func outpointsEqual(a, b wire.OutPoint) bool {
	return a.Hash.String() == b.Hash.String() && a.Index == b.Index
}

// Build and broadcast a transaction that sweeps all coins from an address. If it is a p2sh multisig, the redeemScript must be included
func (w *Wallet) SweepAddress(utxos []wallet.Utxo, address *btc.Address, key *hd.ExtendedKey, redeemScript *[]byte, feeLevel wallet.FeeLevel) (*chainhash.Hash, error) {
	<-w.initChan
	var internalAddr btc.Address
	if address != nil {
		internalAddr = *address
	} else {
		internalAddr = w.CurrentAddress(wallet.INTERNAL)
	}
	script, err := PayToAddrScript(internalAddr)
	if err != nil {
		return nil, err
	}

	var val int64
	var inputs []*wire.TxIn
	additionalPrevScripts := make(map[wire.OutPoint][]byte)
	for _, u := range utxos {
		val += u.Value
		in := wire.NewTxIn(&u.Op, []byte{}, [][]byte{})
		inputs = append(inputs, in)
		additionalPrevScripts[u.Op] = u.ScriptPubkey
	}
	out := wire.NewTxOut(val, script)

	txType := spvwallet.P2PKH
	if redeemScript != nil {
		txType = spvwallet.P2SH_1of2_Multisig
	}

	estimatedSize := spvwallet.EstimateSerializeSize(len(utxos), []*wire.TxOut{out}, false, txType)

	// Calculate the fee
	feePerKb, err := w.insight.EstimateFee(1)
	if err != nil {
		return nil, err
	}
	if feePerKb <= 0 {
		feePerKb = 50000
	}
	fee := estimatedSize * (feePerKb / 1000)

	outVal := val - int64(fee)
	if outVal < 0 {
		outVal = 0
	}
	out.Value = outVal

	tx := &wire.MsgTx{
		Version:  wire.TxVersion,
		TxIn:     inputs,
		TxOut:    []*wire.TxOut{out},
		LockTime: 0,
	}

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	// Sign tx
	getKey := txscript.KeyClosure(func(addr btc.Address) (*btcec.PrivateKey, bool, error) {
		privKey, err := key.ECPrivKey()
		if err != nil {
			return nil, false, err
		}
		wif, err := btc.NewWIF(privKey, w.Params(), true)
		if err != nil {
			return nil, false, err
		}
		return wif.PrivKey, wif.CompressPubKey, nil
	})
	getScript := txscript.ScriptClosure(func(addr btc.Address) ([]byte, error) {
		if redeemScript == nil {
			return []byte{}, nil
		}
		return *redeemScript, nil
	})

	for i, txIn := range tx.TxIn {
		prevOutScript := additionalPrevScripts[txIn.PreviousOutPoint]
		script, err := txscript.SignTxOutput(w.Params(),
			tx, i, prevOutScript, txscript.SigHashAll, getKey,
			getScript, txIn.SignatureScript)
		if err != nil {
			return nil, errors.New("Failed to sign transaction")
		}
		txIn.SignatureScript = script
	}

	// Broadcast
	if _, err = w.broadcastWireTx(tx); err != nil {
		return nil, err
	}
	txid := tx.TxHash()
	return &txid, nil
}

// Create a signature for a multisig transaction
func (w *Wallet) CreateMultisigSignature(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, key *hd.ExtendedKey, redeemScript []byte, feePerByte uint64) ([]wallet.Signature, error) {
	if len(outs) <= 0 {
		return nil, fmt.Errorf("transaction has no outputs")
	}
	var sigs []wallet.Signature
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range ins {
		ch, err := chainhash.NewHashFromStr(hex.EncodeToString(in.OutpointHash))
		if err != nil {
			return sigs, err
		}
		outpoint := wire.NewOutPoint(ch, in.OutpointIndex)
		input := wire.NewTxIn(outpoint, []byte{}, [][]byte{})
		tx.TxIn = append(tx.TxIn, input)
	}
	for _, out := range outs {
		output := wire.NewTxOut(out.Value, out.ScriptPubKey)
		tx.TxOut = append(tx.TxOut, output)
	}

	// Subtract fee
	estimatedSize := spvwallet.EstimateSerializeSize(len(ins), tx.TxOut, false, spvwallet.P2SH_2of3_Multisig)
	fee := estimatedSize * int(feePerByte)
	feePerOutput := fee / len(tx.TxOut)
	for _, output := range tx.TxOut {
		output.Value -= int64(feePerOutput)
	}

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	signingKey, err := key.ECPrivKey()
	if err != nil {
		return sigs, err
	}

	for i := range tx.TxIn {
		sig, err := txscript.RawTxInSignature(tx, i, redeemScript, txscript.SigHashAll, signingKey)
		if err != nil {
			continue
		}
		bs := wallet.Signature{InputIndex: uint32(i), Signature: sig}
		sigs = append(sigs, bs)
	}
	return sigs, nil
}

// Combine signatures and optionally broadcast
func (w *Wallet) Multisign(ins []wallet.TransactionInput, outs []wallet.TransactionOutput, sigs1 []wallet.Signature, sigs2 []wallet.Signature, redeemScript []byte, feePerByte uint64, broadcast bool) ([]byte, error) {
	<-w.initChan
	tx := wire.NewMsgTx(wire.TxVersion)
	for _, in := range ins {
		ch, err := chainhash.NewHashFromStr(hex.EncodeToString(in.OutpointHash))
		if err != nil {
			return nil, err
		}
		outpoint := wire.NewOutPoint(ch, in.OutpointIndex)
		input := wire.NewTxIn(outpoint, []byte{}, [][]byte{})
		tx.TxIn = append(tx.TxIn, input)
	}
	for _, out := range outs {
		output := wire.NewTxOut(out.Value, out.ScriptPubKey)
		tx.TxOut = append(tx.TxOut, output)
	}

	// Subtract fee
	estimatedSize := spvwallet.EstimateSerializeSize(len(ins), tx.TxOut, false, spvwallet.P2SH_2of3_Multisig)
	fee := estimatedSize * int(feePerByte)
	feePerOutput := fee / len(tx.TxOut)
	for _, output := range tx.TxOut {
		output.Value -= int64(feePerOutput)
	}

	// BIP 69 sorting
	txsort.InPlaceSort(tx)

	for i, input := range tx.TxIn {
		var sig1 []byte
		var sig2 []byte
		for _, sig := range sigs1 {
			if int(sig.InputIndex) == i {
				sig1 = sig.Signature
			}
		}
		for _, sig := range sigs2 {
			if int(sig.InputIndex) == i {
				sig2 = sig.Signature
			}
		}
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0)
		builder.AddData(sig1)
		builder.AddData(sig2)
		builder.AddData(redeemScript)
		scriptSig, err := builder.Script()
		if err != nil {
			return nil, err
		}
		input.SignatureScript = scriptSig
	}
	if broadcast {
		if _, err := w.broadcastWireTx(tx); err != nil {
			return nil, err
		}
	}
	var buf bytes.Buffer
	tx.BtcEncode(&buf, 1, wire.BaseEncoding)
	return buf.Bytes(), nil
}

// Generate a multisig script from public keys. If a timeout is included the returned script should be a timelocked escrow which releases using the timeoutKey.
func (w *Wallet) GenerateMultisigScript(keys []hd.ExtendedKey, threshold int, timeout time.Duration, timeoutKey *hd.ExtendedKey) (addr btc.Address, redeemScript []byte, err error) {
	var addrPubKeys []*btc.AddressPubKey
	for _, key := range keys {
		ecKey, err := key.ECPubKey()
		if err != nil {
			return nil, nil, err
		}
		k, err := btc.NewAddressPubKey(ecKey.SerializeCompressed(), w.Params())
		if err != nil {
			return nil, nil, err
		}
		addrPubKeys = append(addrPubKeys, k)
	}
	redeemScript, err = txscript.MultiSigScript(addrPubKeys, threshold)
	if err != nil {
		return nil, nil, err
	}
	addr, err = NewAddressScriptHash(redeemScript, w.Params())
	if err != nil {
		return nil, nil, err
	}
	return addr, redeemScript, nil
}

// Add a script to the wallet and get notifications back when coins are received or spent from it
func (w *Wallet) AddWatchedScript(script []byte) error {
	if addr, err := w.ScriptToAddress(script); err == nil {
		w.addWatchedAddr(addr)
	}
	err := w.DB.WatchedScripts().Put(script)
	w.txStore.PopulateAdrs()
	return err
}

func (w *Wallet) addWatchedAddr(addr btc.Address) {
	w.addrSubscriptionsMutex.Lock()
	if _, ok := w.addrSubscriptions[addr]; !ok {
		w.addrSubscriptions[addr] = struct{}{}
		w.insight.ListenAddress(addr)
	}
	w.addrSubscriptionsMutex.Unlock()
}

// Add a callback for incoming transactions
func (w *Wallet) AddTransactionListener(callback func(wallet.TransactionCallback)) {
	w.listeners = append(w.listeners, callback)
}

func (w *Wallet) ReSyncBlockchain(fromDate time.Time) {
	<-w.initChan
	/*
		_, err := w.findHeightBeforeTime(fromDate)
		if err != nil {
			log.Error(err)
			return
		}
	*/
	panic("not implemented")
}

/*
func (w *Wallet) findHeightBeforeTime(ts time.Time) (int32, error) {
	// Get the best block hash
	resp, err := w.rpcClient.RawRequest("getbestblockhash", []json.RawMessage{})
	if err != nil {
		return 0, err
	}
	hash := string(resp)[1 : len(string(resp))-1]

	// Iterate over the block headers to check the timestamp
	for {
		h := `"` + hash + `"`
		resp, err = w.rpcClient.RawRequest("getblockheader", []json.RawMessage{json.RawMessage(h)})
		if err != nil {
			return 0, err
		}
		type Respose struct {
			Timestamp int64  `json:"time"`
			PrevBlock string `json:"previousblockhash"`
			Height    int32  `json:"height"`
		}
		r := new(Respose)
		err = json.Unmarshal([]byte(resp), r)
		if err != nil {
			return 0, err
		}
		t := time.Unix(r.Timestamp, 0)
		if t.Before(ts) || r.Height == 1 {
			return r.Height, nil
		}
		hash = r.PrevBlock
	}
}
*/

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
	w.insight.Close()
}
