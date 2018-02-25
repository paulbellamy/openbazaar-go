package zcash

import (
	"fmt"
	"golang.org/x/net/proxy"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcashd"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	btc "github.com/btcsuite/btcutil"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func init() {
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getTransactions:   func(addrs []btc.Address) ([]client.Transaction, error) { return nil, nil },
			transactionNotify: func() <-chan client.Transaction { return nil },
		}, nil
	}
}

func testConfig(t *testing.T) Config {
	return Config{
		Mnemonic:    "",
		Params:      &chaincfg.TestNet3Params,
		RepoPath:    "",
		TrustedPeer: "",
		DB: &FakeDatastore{
			keys: &FakeKeystore{
				getLookaheadWindows: func() map[wallet.KeyPurpose]int {
					return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
				},
			},
		},
		Proxy: nil,
	}
}

func TestNewWalletDialsTheInsightAPI(t *testing.T) {
	t.Error("pending")
}

func TestWalletMnemonicDeterminesMasterKey(t *testing.T) {
	t.Error("pending")
}

func TestWalletParams(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.Params{Name: "TestParams"}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	if w.Params() != config.Params {
		t.Errorf(
			"Params() did not return chain cfg params.\nExpected: %v\n     Got: %v",
			config.Params,
			w.Params(),
		)
	}
}

func TestWalletIsDust(t *testing.T) {
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, amount := range []int64{0, 1e2 - 1, 400} {
		t.Run(fmt.Sprint(amount), func(t *testing.T) {
			if !w.IsDust(amount) {
				t.Errorf("Expected IsDust to be true")
			}
		})
	}
	for _, amount := range []int64{(1e3) + 1, 1e4} {
		t.Run(fmt.Sprint(amount), func(t *testing.T) {
			if w.IsDust(amount) {
				t.Errorf("Expected IsDust to be false")
			}
		})
	}
}

func TestWalletCurrencyCodeMainNet(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	expected := "zec"
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletCurrencyCodeTestnet(t *testing.T) {
	expected := "tzec"
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if w.CurrencyCode() != expected {
		t.Errorf(
			"CurrencyCode() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			w.CurrencyCode(),
		)
	}
}

func TestWalletCurrentAddress(t *testing.T) {
	// Generate a key, and initialize the wallet with it.
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	config.Mnemonic = "" // TODO: Set this
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	// Derive the first unused key's address
	_, external, _ := keys.Bip44Derivation(mPrivKey, keys.Zcash)
	externalChild, _ := external.Child(0)
	// Setup the keystore so the first key is unused.
	config.DB = &FakeDatastore{
		keys: &FakeKeystore{
			getUnused: func(p wallet.KeyPurpose) ([]int, error) { return []int{0}, nil },
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	address := w.CurrentAddress(wallet.EXTERNAL)

	if !strings.HasPrefix(fmt.Sprint(address), "t1") || len(fmt.Sprint(address)) != 35 {
		t.Errorf("generated address was not a zcash t-address: %v", address)
	}

	pubkey, _ := externalChild.ECPubKey()
	hash, err := zcashd.NewAddressPubKeyHash(btc.Hash160(pubkey.SerializeUncompressed()), config.Params)
	if err != nil {
		t.Fatal(err)
	}
	expected := hash.EncodeAddress()
	if fmt.Sprint(address) != fmt.Sprint(expected) {
		t.Errorf(
			"CurrentAddress() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			address,
		)
	}
}

func TestWalletNewAddress(t *testing.T) {
	// Generate a key, and initialize the wallet with it.
	config := testConfig(t)
	// markKeyAsUsed, should modify the output of getLastKeyIndex
	unused := 0
	config.DB = &FakeDatastore{
		keys: &FakeKeystore{
			put: func(hash160 []byte, keyPath wallet.KeyPath) error { return nil },
			markKeyAsUsed: func(scriptAddress []byte) error {
				unused++
				return nil
			},
			getLastKeyIndex: func(p wallet.KeyPurpose) (int, bool, error) { return unused, false, nil },
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	// Generate some addresses
	addresses := make([]btc.Address, 10)
	for i := 0; i < 10; i++ {
		addresses[i] = w.NewAddress(wallet.EXTERNAL)
	}

	// all addresses should be unique
	addrMap := map[string]struct{}{}
	for _, a := range addresses {
		addrMap[fmt.Sprint(a)] = struct{}{}
	}
	if len(addrMap) != len(addresses) {
		t.Errorf("Found duplicate addresses from NewAddress: %v", addresses)
	}
}

func TestWalletScriptToAddress(t *testing.T) {
	config := testConfig(t)
	config.Params = &chaincfg.MainNetParams
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Test this better
	for _, tc := range []struct {
		name    string
		script  []byte
		address string
		err     error
	}{
		{
			name:    "empty script",
			script:  nil,
			address: "",
			err:     fmt.Errorf("unknown script type"),
		},
		{
			name:    "basic script",
			script:  []byte{0xa9, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87},
			address: "t3JZcvsuaXE6ygokL4XUiZSTrQBUoPYFnXJ",
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := w.ScriptToAddress([]byte(tc.script))
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n     Got: %v", tc.err, err)
			}
			if tc.address != "" || address != nil {
				if fmt.Sprint(address) != tc.address {
					t.Errorf("\nExpected: %v\n     Got: %v", tc.address, address)
				}
			}
		})
	}
}

func TestWalletDecodeAddress(t *testing.T) {
	w, err := NewWallet(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}

	// TODO: Test this better
	for _, tc := range []struct {
		name    string
		address string
		err     error
	}{
		{
			name:    "empty address",
			address: "",
			err:     fmt.Errorf("decoded address is of unknown format"),
		},
		{
			name:    "basic address",
			address: "tmG2NhraCEiMeaajMjLraFjKVeGP8RWZXz6",
			err:     nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			address, err := w.DecodeAddress(tc.address)
			switch {
			case tc.err == nil && err != nil:
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			case tc.err != nil && err == nil:
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			case tc.err != nil && err != nil && tc.err.Error() != err.Error():
				t.Errorf("\nUnexpected error: %v\n             Got: %v", tc.err, err)
			}

			// re-encoding it should equal the original input
			if address != nil {
				output := address.EncodeAddress()
				if tc.address != output {
					t.Errorf("\nExpected: %v\n     Got: %v", tc.address, address)
				}
			}
		})
	}
}

// TODO: test it ignores watch-only
// TODO: test unconfirmed
func TestWalletBalance(t *testing.T) {
	config := testConfig(t)
	db := config.DB.(*FakeDatastore)

	hash1, _ := chainhash.NewHashFromStr("a")
	hash2, _ := chainhash.NewHashFromStr("b")
	db.utxos = &FakeUtxos{
		getAll: func() ([]wallet.Utxo, error) {
			return []wallet.Utxo{
				{
					Op:       wire.OutPoint{Hash: *hash1},
					AtHeight: 4, // Confirmed
					Value:    1,
				},
				{
					Op:       wire.OutPoint{Hash: *hash2},
					AtHeight: 0, // Unconfirmed
					Value:    2,
				},
			}, nil
		},
	}
	db.stxos = &FakeStxos{
		getAll: func() ([]wallet.Stxo, error) {
			return []wallet.Stxo{
				// Confirm the first txn
				{SpendHeight: 4, SpendTxid: *hash1},
			}, nil
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	confirmed, unconfirmed := w.Balance()

	expectedConfirmed, expectedUnconfirmed := int64(1), int64(2)
	if confirmed != expectedConfirmed {
		t.Errorf("Confirmed\nExpected: %v\n     Got: %v", expectedConfirmed, confirmed)
	}
	if unconfirmed != expectedUnconfirmed {
		t.Errorf("Unconfirmed\nExpected: %v\n     Got: %v", expectedUnconfirmed, unconfirmed)
	}
}

// TODO: Test initial load of transactions
// TODO: Test ongoing transactions
// TODO: Test race condition of transactions coming in after initial load
func TestWalletTransactionsInitialLoad(t *testing.T) {
	txnChan := make(chan client.Transaction)
	newInsightClient = func(url string, proxyDialer proxy.Dialer) (InsightClient, error) {
		return &FakeInsightClient{
			getTransactions: func(addrs []btc.Address) ([]client.Transaction, error) {
				// TODO: Put some txns here
				return []client.Transaction{{Txid: "a"}}, nil
			},
			transactionNotify: func() <-chan client.Transaction { return txnChan },
		}, nil
	}
	config := testConfig(t)
	expectedTxns := []wallet.Txn{{Txid: "a"}}
	config.DB = &FakeDatastore{
		keys: &FakeKeystore{
			getAll: func() ([]wallet.KeyPath, error) {
				return []wallet.KeyPath{{wallet.EXTERNAL, 0}}, nil
			},
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
		},
		txns: &FakeTxns{
			put: func(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
				return nil
			},
			getAll: func(includeWatchOnly bool) ([]wallet.Txn, error) {
				return expectedTxns, nil
			},
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}
	w.Start()
	defer w.Close()

	txns, err := w.Transactions()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(txns, expectedTxns) {
		t.Errorf("\nExpected: %v\n     Got: %v", expectedTxns, txns)
	}
}
