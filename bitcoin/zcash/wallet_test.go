package zcash

import (
	"fmt"
	"testing"

	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func testConfig(t *testing.T) Config {
	return Config{
		Mnemonic:    "",
		Params:      &chaincfg.TestNet3Params,
		RepoPath:    "",
		TrustedPeer: "",
		DB: &FakeKeystore{
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
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
	// TODO: Check this key is fetched from the db
	config := testConfig(t)
	config.Mnemonic = "" // TODO: Set this
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	// Derive the first unused key's address
	_, external, _ := keys.Bip44Derivation(mPrivKey, keys.Zcash)
	externalChild, _ := external.Child(0)
	// Setup the keystore so the first key is unused.
	config.DB = &FakeKeystore{
		getUnused: func(p wallet.KeyPurpose) ([]int, error) { return []int{0}, nil },
		getLookaheadWindows: func() map[wallet.KeyPurpose]int {
			return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
		},
	}
	w, err := NewWallet(config)
	if err != nil {
		t.Fatal(err)
	}

	address := w.CurrentAddress(wallet.EXTERNAL)

	expected, _ := externalChild.Address(config.Params)
	if fmt.Sprint(address) != fmt.Sprint(expected) {
		t.Errorf(
			"CurrentAddress() did not return expected.\nExpected: %v\n     Got: %v",
			expected,
			address,
		)
	}
}

func TestWalletScriptToAddress(t *testing.T) {
	w, err := NewWallet(testConfig(t))
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
			address: "t26YoyZ1iPgiMEWL4zGUm74eVWfhyDMXzY2",
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
